# Copyright (c) 2019 Renaissance Computing Institute, except where noted.
# All rights reserved.
#
# This software is released under GPLv2
#
# Renaissance Computing Institute,
# (A Joint Institute between the University of North Carolina at Chapel Hill,
# North Carolina State University, and Duke University)
# http://www.renci.org
#
# For questions, comments please contact software@renci.org
#
# This software simplifies post-boot configuration of a guest VM based on
# user data passed to an EC2/Eucalyptus instance. More information at
# http://geni-orca.renci.org
#
# Author: (Komal Thareja kthare10@renci.org)

import os
import re
import socket
import subprocess
import time
import glob
import json
import sys

import logging
import logging.handlers

from comet_common_iface import *
from monitor import *
from optparse import OptionParser
from daemon import runner

from host_key_tools.util import Commands
from host_key_tools import CONFIG, LOGGER

#LOGGER = 'hostkey_daemon'

class HostNamePubKeyCustomizer():

    def __init__(self, cometHost, sliceId, readToken, writeToken, rId, kafkahost):
        self.cometHost = cometHost
        self.sliceId = sliceId
        self.readToken = readToken
        self.writeToken = writeToken
        self.rId = rId
        self.hostName = rId
        self.ip = None
        self.hostsFile = '/etc/hosts'
        self.keysFile = '/root/.ssh/authorized_keys'
        self.publicKey = '/root/.ssh/id_rsa.pub'
        self.neucaPubKeysStr = ('NEuca comet pubkeys modifications - ' +
                    'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        self.neucaUserKeysStr = ('NEuca comet user keys modifications - ' +
                    'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.stateDir = '/var/lib/hostkey'
        self.pidDir = '/var/run'
        self.pidfile_path = (self.pidDir + '/' + "hostkey.pid" )
        self.pidfile_timeout = 10000
        self.kafkahost = kafkahost


        self.log = logging.getLogger(LOGGER)

        # Need to ensure that the state directory is created.
        if not os.path.exists(self.stateDir):
            os.makedirs(self.stateDir)

        # Ditto for PID directory.
        if not os.path.exists(self.pidDir):
            os.makedirs(self.pidDir)

    def getPublicIP(self):
        try:
             cmd = ["/bin/curl", "-s", "http://169.254.169.254/2009-04-04/meta-data/public-ipv4"]
             (rtncode, data_stdout, data_stderr) = Commands.run(cmd, timeout=60)
             self.ip = data_stdout.strip()
        except Exception as e:
             self.log.exception('Failed to obtain public ip using command: ' + str(cmd))
             self.log.error('Exception was of type: %s' % (str(type(e))))


    def __updateHostsFileWithCometHosts(self, newHosts):
        """
        Maintains the comet entries added to /etc/hosts.
        """
        neucaStr = ('NEuca comet modifications - ' +
                    'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        startStr = '### BEGIN ' + neucaStr
        endStr = '### END ' + neucaStr

        fd = None
        try:
            fd = open(self.hostsFile, 'a+')
        except:
            self.log.error('__updateHostsFileWithCometHosts:Unable to open ' + self.hostsFile +
                           ' for modifications!')
            return

        fd.seek(0)
        hostsEntries = list(fd)
        modified = False

        neucaStartEntry = None
        neucaEndEntry = None
        try:
            neucaStartEntry = hostsEntries.index(startStr)
            neucaEndEntry = hostsEntries.index(endStr)
        except ValueError:
            pass

        if neucaStartEntry is not None :
            existingHosts = []
            if neucaStartEntry+1 != neucaEndEntry :
                existingHosts = hostsEntries[neucaStartEntry+1:neucaEndEntry]
                existingHosts.sort()
            if cmp(existingHosts, newHosts) :
                del hostsEntries[neucaStartEntry:neucaEndEntry+1]
                modified = True
            else:
                self.log.debug("__updateHostsFileWithCometHosts: Nothing to do")
        else:
            modified = True

        if modified:
            hostsEntries.append(startStr)
            for line in newHosts:
                hostsEntries.append(line)
            hostsEntries.append(endStr)
            try:
                fd.seek(0)
                fd.truncate()
                for line in hostsEntries:
                    fd.write(line)
            except Exception as e:
                self.log.error('__updateHostsFileWithCometHosts: Error writing modifications to ' +
                               self.hostsFile)
                self.log.error('__updateHostsFileWithCometHosts: Exception was of type: %s' % (str(type(e))))
                self.log.error('__updateHostsFileWithCometHosts: Exception : %s' % (str(e)))
        fd.close()

    def updateHostsFromComet(self):
        try:
            self.log.debug("Updating hosts locally")

            section = "hostsall"
            newHosts = []
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            self.log.debug("Processing section " + section)
            resp = comet.invokeRoundRobinApi('enumerate_families', self.sliceId, None, self.readToken, None, section, None)

            if resp.status_code != 200:
                self.log.error("Failure occured in enumerating family from comet" + section)
                return

            if resp.json()["value"] and resp.json()["value"]["entries"]:
                for e in resp.json()["value"]["entries"]:
                    if e["key"] == self.rId :
                        continue

                    self.log.debug("processing " + e["key"])
                    if e["value"] == "\"\"" :
                        continue
                    hosts = json.loads(json.loads(e["value"])["val_"])
                    for h in hosts:
                        if h["ip"] == "" :
                            continue

                        self.log.debug("check if " + h["hostName"] + " exists")
                        newHostsEntry = h["ip"] + '\t' + h["hostName"] + '\n'
                        newHostsEntry = newHostsEntry.replace('/','-')
                        newHosts.append(str(newHostsEntry))

            if newHosts is not None:
                newHosts.sort()
                self.__updateHostsFileWithCometHosts(newHosts)
        except Exception as e:
            self.log.error('updateHostsFromComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updateHostsFromComet: Exception : %s' % (str(e)))

    def __updateAuthorizedKeysFile(self, newKeys, startStr, endStr, keysFile):
        """
        Maintains the comet entries added to authorized_keys.
        """

        fd = None
        try:
            fd = open(keysFile, 'a+')
        except:
            self.log.error('__updateAuthorizedKeysFile: Unable to open ' + keysFile +
                           ' for modifications!')
            return

        fd.seek(0)
        keysEntries = list(fd)
        modified = False

        neucaStartEntry = None
        neucaEndEntry = None
        try:
            neucaStartEntry = keysEntries.index(startStr)
            neucaEndEntry = keysEntries.index(endStr)
        except ValueError:
            pass

        if neucaStartEntry is not None and neucaEndEntry is not None:
            existingKeys = []
            if neucaStartEntry+1 != neucaEndEntry :
                existingKeys = keysEntries[neucaStartEntry+1:neucaEndEntry]
                existingKeys.sort()
            if cmp(existingKeys, newKeys) :
                del keysEntries[neucaStartEntry:neucaEndEntry+1]
                modified = True
            else:
                self.log.debug("__updateAuthorizedKeysFile: Nothing to do")
        else:
            modified = True

        if modified:
            keysEntries.append(startStr)
            for line in newKeys:
                keysEntries.append(line)
            keysEntries.append(endStr)
            try:
                fd.seek(0)
                fd.truncate()
                for line in keysEntries:
                    fd.write(line)
            except Exception as e:
                self.log.error('__updateAuthorizedKeysFile: Error writing modifications to ' +
                               self.hostsFile)
                self.log.error('__updateAuthorizedKeysFile: Exception was of type: %s' % (str(type(e))))
                self.log.error('__updateAuthorizedKeysFile: Exception : %s' % (str(e)))
        fd.close()

    def updatePubKeysFromComet(self):
        try:
            self.log.debug("Updating PubKeys locally")

            if self.sliceId is None or self.readToken is None or self.writeToken is None:
                return
            startStr = '### BEGIN ' + self.neucaPubKeysStr
            endStr = '### END ' + self.neucaPubKeysStr
            section = "pubkeysall"
            newKeys = []
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            self.log.debug("Processing section " + section)
            resp = comet.invokeRoundRobinApi('enumerate_families', self.sliceId, None, self.readToken, None, section, None)
            if resp.status_code != 200:
                self.log.error("Failure occured in enumerating family from comet" + section)
                return
            if resp.json()["value"] and resp.json()["value"]["entries"]:
                for e in resp.json()["value"]["entries"]:
                    if e["key"] == self.rId :
                        continue
                    self.log.debug("processing " + e["key"])
                    if e["value"] == "\"\"" :
                        continue
                    keys = json.loads(json.loads(e["value"])["val_"])
                    for k in keys:
                        if k["publicKey"] == "" :
                            continue
                        newKeys.append(k["publicKey"])

            if newKeys is not None:
                newKeys.sort()
                self.__updateAuthorizedKeysFile(newKeys, startStr, endStr, self.keysFile)
        except Exception as e:
            self.log.error('updatePubKeysFromComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updatePubKeysFromComet: Exception : %s' % (str(e)))


    def updatePubKeysToComet(self):
        try:
            self.log.debug("Updating PubKeys in comet")
            if self.sliceId is not None and self.rId is not None and self.readToken is not None and self.writeToken is not None:
                checker = None
                section = "pubkeysall"
                comet = CometInterface(self.cometHost, None, None, None, self.log)
                self.log.debug("Processing section " + section)
                keys = self.getCometData(section)
                if keys is None:
                    self.log.debug("empty section " + section)
                    return
                for k in keys:
                    if k["publicKey"] == "" :
                        rtncode = 1
                        if os.path.exists(self.publicKey) :
                            self.log.debug("Public Key already exists for root user")
                            rtncode = 0
                        else :
                            self.log.debug("Generating key for root user")
                            cmd = [
                            "/bin/ssh-keygen", "-t", "rsa", "-N", "", "-f", "/root/.ssh/id_rsa"
                            ]
                            FNULL = open(os.devnull, 'w')
                            rtncode = subprocess.call(cmd, stdout=FNULL)
                        if rtncode == 0:
                            self.log.debug("Pushing public key for root user to Comet")
                            f = open(self.publicKey, 'r')
                            keyVal= f.read()
                            f.close()
                            k["publicKey"]=keyVal
                            checker = True
                        else:
                            self.log.error("Failed to generate keys for root user")
                if checker :
                    val = {}
                    val["val_"] = json.dumps(keys)
                    newVal = json.dumps(val)
                    self.log.debug("Updating " + section + "=" + newVal)
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken, self.writeToken, section, json.loads(newVal))
                    if resp.status_code != 200:
                        self.log.error("Failure occured in updating pubkeys to comet" + section)
                else :
                    self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('updatePubKeysToComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updatePubKeysToComet: Exception : %s' % (str(e)))

    def updateHostsToComet(self):
        try:
            self.log.debug("Updating Hosts in comet")
            if self.sliceId is not None and self.rId is not None and self.readToken is not None and self.writeToken is not None:
                checker = None
                section = "hostsall"
                comet = CometInterface(self.cometHost, None, None, None, self.log)
                self.log.debug("Processing section " + section)
                hosts = self.getCometData(section)
                if hosts is None:
                    self.log.debug("empty section " + section)
                    return
                for h in hosts :
                    self.log.debug("Processing host " + h["hostName"])
                    self.log.debug("h[ip]=" + h["ip"] + " ip=" + self.ip)
                    if h["hostName"].replace('/','-') == self.hostName and h["ip"] == "" :
                    #if h["hostName"].replace('/','-') == self.hostName and h["ip"] != self.ip :
                         h["ip"] = self.ip
                         checker = True
                if checker :
                    val = {}
                    val["val_"] = json.dumps(hosts)
                    newVal = json.dumps(val)
                    self.log.debug("Updating " + section + "=" + newVal)
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken, self.writeToken, section, json.loads(newVal))
                    if resp.status_code != 200:
                        self.log.debug("Failure occured in updating hosts to comet" + section)
                else :
                    self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('updateHostsToComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('updateHostsToComet: Exception : %s' % (str(e)))

    def getCometData(self, section):
        if self.sliceId is not None and self.rId is not None and self.readToken is not None:
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            resp = comet.invokeRoundRobinApi('get_family', self.sliceId, self.rId, self.readToken, None, section, None)
            if resp.status_code != 200:
                self.log.error("Failure occured in fetching family from comet" + section)
                return None
            if resp.json()["value"].get("error") :
                self.log.error("Error occured in fetching family from comet" + section + resp.json()["value"]["error"])
                return None
            elif resp.json()["value"] :
                value = resp.json()["value"]["value"]
                if value is not None :
                    secData = json.loads(json.loads(value)["val_"])
                    return secData
            else:
                return None
        else :
            self.log.error("sliceId/rId/readToken could not be determined")
            return None

    def monitorAndSendToComet(self):
        try:
            self.log.debug("monitorAndSendToComet:Updating resourcesall in comet")
            if self.sliceId is not None and self.rId is not None and self.readToken is not None and self.writeToken is not None:
                checker = None
                section = "resourcesall"
                comet = CometInterface(self.cometHost, None, None, None, self.log)
                self.log.debug("monitorAndSendToComet:Processing section " + section)
                resources = self.getCometData(section)
                if resources is None:
                    self.log.debug("monitorAndSendToComet:empty section " + section)
                    return
                for r in resources:
                    self.log.debug(r)
                    if "cpu" in r :
                        cpuUsage = psutil.cpu_times_percent()._asdict()
                        if r["cpu"] != cpuUsage :
                            r["cpu"] = cpuUsage
                            checker = True
                    if "memory" in r :
                        memUsage = psutil.virtual_memory()._asdict()
                        if r["memory"] != memUsage :
                            r["memory"] = memUsage
                            checker = True
                    if "disk" in r :
                        diskUsage = psutil.disk_usage("/")._asdict()
                        if r["disk"] != diskUsage :
                            r["disk"] = diskUsage
                            checker = True
                if checker :
                    val = {}
                    val["val_"] = json.dumps(resources)
                    newVal = json.dumps(val)
                    self.log.debug("Updating " + section + "=" + newVal)
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken, self.writeToken, section, json.loads(newVal))
                    if resp.status_code != 200:
                        self.log.error("monitorAndSendToComet:Failure occured in updating resourcesall to comet" + section)
                else :
                    self.log.debug("monitorAndSendToComet:Nothing to update")
        except Exception as e:
            self.log.error('monitorAndSendToComet: Exception was of type: %s' % (str(type(e))))
            self.log.error('monitorAndSendToComet: Exception : %s' % (str(e)))

    def monitorResources(self):
        if self.kafkahost is not None:
            mon=ResourceMonitor(self.sliceId, self.kafkahost, self.log)
            mon.monitorAndSend()
        else:
            self.monitorAndSendToComet()

    def run(self):
        while True:
            try:
                self.getPublicIP()
                self.log.debug('Polling')
                self.updateHostsToComet()
                self.updatePubKeysToComet()
                self.updatePubKeysFromComet()
                self.updateHostsFromComet()
                self.monitorResources()
                self.firstRun = False
            except KeyboardInterrupt:
                self.log.error('Terminating on keyboard interrupt...')
                sys.exit(0)
            except Exception as e:
                self.log.exception(('Caught exception in daemon loop; ' +
                                    'backtrace follows.'))
                self.log.error('Exception was of type: %s' % (str(type(e))))
            time.sleep(10)

def main():
    usagestr = 'Usage: %prog start|stop|restart options'
    parser = OptionParser(usage=usagestr)
    parser.add_option(
        '-c',
        '--cometHost',
        dest='cometHost',
        type = str,
        help='Comet Host'
    )
    parser.add_option(
        '-s',
        '--sliceId',
        dest='sliceId',
        type = str,
        help='Slice Id'
    )
    parser.add_option(
        '-r',
        '--readToken',
        dest='readToken',
        type = str,
        help='Read Token'
    )
    parser.add_option(
        '-w',
        '--writeToken',
        dest='writeToken',
        type = str,
        help='Write Token'
    )
    parser.add_option(
        '-i',
        '--id',
        dest='id',
        type = str,
        help='id'
    )
    parser.add_option(
        '-k',
        '--kafkahost',
        dest='kafkahost',
        type = str,
        help='kafkahost'
    )

    options, args = parser.parse_args()

    if len(args) != 1:
        parser.print_help()
        sys.exit(1)

    if args[0] == 'start':
        sys.argv = [sys.argv[0], 'start']
    elif args[0] == 'stop':
        sys.argv = [sys.argv[0], 'stop']
    elif args[0] == 'restart':
        sys.argv = [sys.argv[0], 'restart']
    else:
        parser.print_help()
        sys.exit(1)


    initial_log_location = '/dev/tty'
    try:
    	logfd = open(initial_log_location, 'r')
    except:
	    initial_log_location = '/dev/null'
    else:
	    logfd.close()

    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(format=log_format, filename=initial_log_location)
    log = logging.getLogger(LOGGER)
    log.setLevel('DEBUG')

    app = HostNamePubKeyCustomizer(options.cometHost, options.sliceId, options.readToken, options.writeToken, options.id, options.kafkahost)
    daemon_runner = runner.DaemonRunner(app)

    try:

        log_dir = "/var/log/hostkey/"
        log_level = "DEBUG"
        log_file = "hostkey.log"
        log_retain = 5
        log_file_size = 5000000
        log_level = 'DEBUG'

        if not os.path.exists(log_dir):
             os.makedirs(log_dir)

        handler = logging.handlers.RotatingFileHandler(
                 log_dir + '/' + log_file,
                 backupCount=log_retain,
                 maxBytes=log_file_size)
        handler.setLevel(log_level)
        formatter = logging.Formatter(log_format)
        handler.setFormatter(formatter)

        log.addHandler(handler)
        log.propagate = False
        log.info('Logging Started')

        daemon_runner.daemon_context.files_preserve = [
                 handler.stream,
             ]


        log.info('Administrative operation: %s' % args[0])
        daemon_runner.do_action()
        log.info('Administrative after action: %s' % args[0])
    except runner.DaemonRunnerStopFailureError as drsfe:
        log.propagate = True
        log.error('Unable to stop service; reason was: %s' % str(drsfe))
        log.error('Exiting...')
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
