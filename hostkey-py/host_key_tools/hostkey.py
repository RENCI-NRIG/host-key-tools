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
import socket
import subprocess
import threading
import time
import json
import sys
import logging
from logging.handlers import RotatingFileHandler
import traceback

from optparse import OptionParser

from .comet_common_iface import CometInterface
from .monitor import ResourceMonitor
from .script import Script
from . import LOGGER
from .graceful_interrupt_handler import GracefulInterruptHandler


class HostNamePubKeyCustomizer:
    def __init__(self, cometHost: str, sliceId: str, readToken: str, writeToken: str, rId, kafkahost: str,
                 kafkaTopic: str, family: str):
        self.firstRun = True
        self.cometHost = cometHost
        self.sliceId = sliceId
        self.readToken = readToken
        self.writeToken = writeToken
        self.family = family
        if rId is None:
            rId = socket.gethostname()
        self.rId = rId
        self.hostName = rId
        self.ip = None
        self.hostsFile = '/etc/hosts'
        self.keysFile = '/root/.ssh/authorized_keys'
        self.publicKey = '/root/.ssh/id_rsa.pub'
        self.privateKey = '/root/.ssh/id_rsa'
        self.neucaPubKeysStr = ('NEuca comet pubkeys modifications - '
                                'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        self.neucaUserKeysStr = ('NEuca comet user keys modifications - '
                                 'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.stateDir = '/var/lib/hostkey'
        self.public_ips = f"{self.stateDir}/public.json"
        self.pidDir = '/var/run'
        self.pidfile_path = (self.pidDir + '/' + "hostkey.pid" )
        self.pidfile_timeout = 10000
        self.kafkahost = kafkahost
        self.kafkaTopic = kafkaTopic

        self.log = logging.getLogger(LOGGER)

        # Need to ensure that the state directory is created.
        if not os.path.exists(self.stateDir):
            os.makedirs(self.stateDir)

        # Ditto for PID directory.
        if not os.path.exists(self.pidDir):
            os.makedirs(self.pidDir)

        self.thread = None
        self.stopped = False

    def start(self):
        """
        Start the daemon
        """
        try:
            if self.thread is not None:
                raise Exception("hostkey daemon has already been started")

            self.thread = threading.Thread(target=self.run)
            self.thread.setName("hostkeyd")
            self.thread.setDaemon(True)
            self.thread.start()
        except Exception as e:
            self.log.error(f"Failed to start the daemon: {e}")
            self.log.error(traceback.format_exc())

    def stop(self):
        """
        Stop the daemon
        """
        self.stopped = True
        temp = self.thread
        self.thread = None
        if temp is not None:
            self.log.warning("It seems that the hostkeyd thread is running. Interrupting it")
            try:
                temp.join()
            except Exception as e:
                self.log.error("Could not join actor thread {}".format(e))
                self.log.error(traceback.format_exc())

    def get_public_ip(self):
        try:
             cmd = ["/bin/curl", "-s", "http://169.254.169.254/2009-04-04/meta-data/public-ipv4"]
             (rtncode, data_stdout, data_stderr) = subprocess.run(cmd)
             self.ip = data_stdout.strip()
        except Exception as e:
             self.log.exception('Failed to obtain public ip using command: ' + str(cmd))
             self.log.error('Exception was of type: %s' % (str(type(e))))

    def fetch_remote_public_ip(self, host: str) -> str:
        try:
            public_ip = None
            import paramiko
            key = paramiko.RSAKey.from_private_key_file(self.privateKey)
            client = paramiko.SSHClient()
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())

            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(host, username='root', pkey=key)
            stdin, stdout, stderr = client.exec_command("curl http://169.254.169.254/latest/meta-data/public-ipv4")
            if stderr is None:
                public_ip = str(stdout.read(), 'utf-8').replace('\\n', '')
                public_ip = public_ip.strip()
                self.log.debug(f"Public IP for host: {host} {public_ip}")
            client.close()
            return public_ip
        except Exception as e:
            self.log.error(f"Failed to determine public IP for host: {host}: e: {e}")
            self.log.error(traceback.format_exc())

    def fetch_remote_public_ips(self):
        self.log.debug("fetch_remote_public_ips IN")
        try:
            if not os.path.exists(self.privateKey):
                return
            self.log.debug("Updating Public IPs locally")

            ip_hosts = {}
            if os.path.exists(self.public_ips):
                with open(self.public_ips, "r") as f:
                    ip_hosts = json.loads(f.read())

            section = "hosts" + self.family

            comet = CometInterface(self.cometHost, None, None, None, self.log)
            self.log.debug("Processing section " + section)
            resp = comet.invokeRoundRobinApi('enumerate_families', self.sliceId, None, self.readToken, None,
                                             section, None)

            if resp.status_code != 200:
                self.log.error("Failure occurred in enumerating family from comet" + section)
                return

            modified = False
            if resp.json()["value"] and resp.json()["value"]["entries"]:
                for e in resp.json()["value"]["entries"]:
                    if e["key"] == self.rId:
                        continue

                    self.log.debug("processing " + e["key"])
                    if e["value"] == "\"\"":
                        continue
                    try:
                        hosts = json.loads(json.loads(e["value"])["val_"])
                        for h in hosts:
                            if h["ip"] == "":
                                continue
                            host = h["hostName"]

                            if host not in ip_hosts:
                                ip = self.fetch_remote_public_ip(host=host)
                                if ip is not None:
                                    ip_hosts[host] = ip
                                    modified = True

                    except Exception as e:
                        self.log.error('Exception was of type: %s' % (str(type(e))))
                        self.log.error('Exception : %s' % (str(e)))

            if modified:
                with open(self.public_ips, "w") as f:
                    json.dump(ip_hosts, f)

        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))
        finally:
            self.log.debug("fetch_remote_public_ips OUT")

    def __updateHostsFileWithCometHosts(self, newHosts):
        """
        Maintains the comet entries added to /etc/hosts.
        """
        neucaStr = ('NEuca comet modifications - '
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
            if existingHosts != newHosts:
                del hostsEntries[neucaStartEntry:neucaEndEntry+1]
                modified = True
            else:
                self.log.debug("Nothing to do")
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
                self.log.error('Error writing modifications to ' + self.hostsFile)
                self.log.error('Exception was of type: %s' % (str(type(e))))
                self.log.error('Exception : %s' % (str(e)))
        fd.close()

    def updateHostsFromComet(self):
        try:
            self.log.debug("Updating hosts locally")

            section = "hosts" + self.family
            newHosts = []
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            self.log.debug("Processing section " + section)
            resp = comet.invokeRoundRobinApi('enumerate_families', self.sliceId, None, self.readToken, None,
                                             section, None)

            if resp.status_code != 200:
                self.log.error("Failure occurred in enumerating family from comet" + section)
                return

            if resp.json()["value"] and resp.json()["value"]["entries"]:
                for e in resp.json()["value"]["entries"]:
                    if e["key"] == self.rId :
                        continue

                    self.log.debug("processing " + e["key"])
                    if e["value"] == "\"\"" :
                        continue
                    try:
                        hosts = json.loads(json.loads(e["value"])["val_"])
                        for h in hosts:
                            if h["ip"] == "" :
                                continue

                            self.log.debug("check if " + h["hostName"] + " exists")
                            newHostsEntry = h["ip"] + '\t' + h["hostName"] + '\n'
                            newHostsEntry = newHostsEntry.replace('/','-')
                            newHosts.append(str(newHostsEntry))
                    except Exception as e:
                        self.log.error('Exception was of type: %s' % (str(type(e))))
                        self.log.error('Exception : %s' % (str(e)))

            if newHosts is not None:
                newHosts.sort()
                self.__updateHostsFileWithCometHosts(newHosts)
        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))

    def __updateAuthorizedKeysFile(self, newKeys, startStr, endStr, keysFile):
        """
        Maintains the comet entries added to authorized_keys.
        """

        fd = None
        try:
            fd = open(keysFile, 'a+')
        except:
            self.log.error('Unable to open ' + keysFile + ' for modifications!')
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
            if existingKeys != newKeys:
                del keysEntries[neucaStartEntry:neucaEndEntry+1]
                modified = True
            else:
                self.log.debug("Nothing to do")
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
                self.log.error('Error writing modifications to ' + self.hostsFile)
                self.log.error('Exception was of type: %s' % (str(type(e))))
                self.log.error('Exception : %s' % (str(e)))
        fd.close()

    def updatePubKeysFromComet(self):
        try:
            self.log.debug("Updating PubKeys locally")

            if self.sliceId is None or self.readToken is None or self.writeToken is None:
                return
            startStr = '### BEGIN ' + self.neucaPubKeysStr
            endStr = '### END ' + self.neucaPubKeysStr
            section = "pubkeys" + self.family
            newKeys = []
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            self.log.debug("Processing section " + section)
            resp = comet.invokeRoundRobinApi('enumerate_families', self.sliceId, None, self.readToken, None,
                                             section, None)
            if resp.status_code != 200:
                self.log.error("Failure occurred in enumerating family from comet" + section)
                return
            if resp.json()["value"] and resp.json()["value"]["entries"]:
                for e in resp.json()["value"]["entries"]:
                    if e["key"] == self.rId :
                        continue
                    self.log.debug("processing " + e["key"])
                    if e["value"] == "\"\"" :
                        continue
                    try:
                        keys = json.loads(json.loads(e["value"])["val_"])
                        for k in keys:
                            if k["publicKey"] == "" :
                                continue
                            newKeys.append(k["publicKey"])
                    except Exception as e:
                        self.log.error('Exception was of type: %s' % (str(type(e))))
                        self.log.error('Exception : %s' % (str(e)))
            if newKeys is not None:
                newKeys.sort()
                self.__updateAuthorizedKeysFile(newKeys, startStr, endStr, self.keysFile)
        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))

    def updateTokensFromComet(self):
        try:
            self.log.debug("Updating tokens locally")

            if os.path.exists("/home/worker/joined"):
                self.log.debug("Nothing to do!")
                return

            if self.sliceId is None or self.readToken is None or self.writeToken is None:
                return
            section = "tokens" + self.family
            keadm_token = None
            core_ip = None
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            self.log.debug("Processing section " + section)
            resp = comet.invokeRoundRobinApi('enumerate_families', self.sliceId, None, self.readToken, None,
                                             section, None)
            if resp.status_code != 200:
                self.log.error("Failure occurred in enumerating family from comet" + section)
                return
            if resp.json()["value"] and resp.json()["value"]["entries"]:
                for e in resp.json()["value"]["entries"]:
                    if e["key"] == self.rId:
                        continue
                    self.log.debug("processing node: {} value: {}".format(e["key"], e["value"]))
                    if e["value"] == "\"\"":
                        continue
                    try:
                        token_json = json.loads(e["value"])
                        keadm_token = token_json.get("keadmToken", None)
                        core_ip = token_json.get("ip", None)
                        self.log.debug("Token: {} IP: {}".format(keadm_token, core_ip))
                    except Exception as e:
                        self.log.error('Exception was of type: %s' % (str(type(e))))
                        self.log.error('Exception : %s' % (str(e)))
            if keadm_token is not None and core_ip is not None and keadm_token != "" and core_ip != "":
                cmd = [
                    "/bin/su", "-", "worker", "-c",
                    "sudo /home/worker/bin/keadm join --cloudcore-ipport={}:10000 --token={}".format(core_ip, keadm_token)]
                self.log.debug("Joining the Kube Edge master")
                self.log.debug("Running the cmd: {}".format(cmd))
                FNULL = open(os.devnull, 'w')
                rtncode = subprocess.call(cmd, stdout=FNULL)
                if rtncode == 0:
                    self.log.debug("Joined the KEADM")
                    cmd = [
                        "/bin/su", "-", "worker", "-c", "sudo touch /home/worker/joined"]
                    FNULL = open(os.devnull, 'w')
                    rtncode = subprocess.call(cmd, stdout=FNULL)

        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))

    def updatePubKeysToComet(self):
        try:
            self.log.debug("Updating PubKeys in comet")
            if self.sliceId is not None and self.rId is not None and self.readToken is not None and \
                    self.writeToken is not None:
                checker = None
                section = "pubkeys" + self.family
                comet = CometInterface(self.cometHost, None, None, None, self.log)
                self.log.debug("Processing section " + section)
                keys = self.getCometData(section)
                if keys is None:
                    self.log.debug("empty section " + section)
                    return
                for k in keys:
                    if k["publicKey"] == "":
                        rtncode = 1
                        if os.path.exists(self.publicKey):
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
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken,
                                                     self.writeToken, section, json.loads(newVal))
                    if resp.status_code != 200:
                        self.log.error("Failure occurred in updating pubkeys to comet" + section)
                else :
                    self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))

    def updateTokensToComet(self):
        try:
            self.log.debug("Updating Tokens in comet")
            if self.sliceId is not None and self.rId is not None and self.readToken is not None and \
                    self.writeToken is not None:
                checker = None
                section = "tokens" + self.family
                comet = CometInterface(self.cometHost, None, None, None, self.log)
                self.log.debug("Processing section " + section)
                token_info = self.getCometData(section)
                if token_info is None:
                    self.log.debug("empty section " + section)
                    return
                self.log.debug("Processing section " + section + " token_info " + str(token_info))
                if token_info["keadmToken"] == "" and "master" in self.hostName:
                    rtncode = 1
                    self.log.debug("Fetching keadm token")
                    cmd = [
                    "/bin/su", "-", "core", "-c",
                        "sudo /home/core/bin/keadm gettoken --kube-config=/home/core/.kube/config > /tmp/token"]
                    FNULL = open(os.devnull, 'w')
                    rtncode = subprocess.call(cmd, stdout=FNULL)
                    if rtncode == 0:
                        self.log.debug("Pushing keadm token from master to Comet")
                        f = open("/tmp/token", 'r')
                        keyVal= f.read()
                        f.close()
                        token_info["keadmToken"] = keyVal.strip("\n")
                        checker = True
                    else:
                        self.log.error("Failed to fetch Keadm token for master")
                if checker:
                    self.log.debug("Updating " + section + "=" + str(token_info))
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken,
                                                     self.writeToken, section, token_info)
                    if resp.status_code != 200:
                        self.log.error("Failure occurred in updating tokens to comet" + section)
                else:
                    self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))

    def updateHostsToComet(self):
        try:
            self.log.debug("Updating Hosts in comet")
            if self.sliceId is not None and self.rId is not None and self.readToken is not None and \
                    self.writeToken is not None:
                checker = None
                section = "hosts" + self.family
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
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken,
                                                     self.writeToken, section, json.loads(newVal))
                    if resp.status_code != 200:
                        self.log.debug("Failure occurred in updating hosts to comet" + section)
                else :
                    self.log.debug("Nothing to update")
        except Exception as e:
            self.log.error('Exception was of type: %s' % (str(type(e))))
            self.log.error('Exception : %s' % (str(e)))

    def getCometData(self, section):
        if self.sliceId is not None and self.rId is not None and self.readToken is not None:
            comet = CometInterface(self.cometHost, None, None, None, self.log)
            resp = comet.invokeRoundRobinApi('get_family', self.sliceId, self.rId, self.readToken, None, section, None)
            if resp.status_code != 200:
                self.log.error("Failure occurred in fetching family from comet" + section)
                return None
            if resp.json()["value"].get("error"):
                self.log.error("Error occurred in fetching family from comet" + section + resp.json()["value"]["error"])
                return None
            elif resp.json()["value"]:
                value = resp.json()["value"]["value"]
                if value is not None:
                    value_json = json.loads(value)
                    if value_json.get("val_", None) is not None:
                        secData = json.loads(value_json.get("val_"))
                    else:
                        secData = value_json
                    return secData
            else:
                return None
        else :
            self.log.error("sliceId/rId/readToken could not be determined")
            return None

    def updateScriptsFromComet(self):
        try:
            scripts = self.getCometData('scripts')
            if scripts is not None :
                result = []
                for s in scripts:
                    scriptName=s["scriptName"].encode('utf-8').strip()
                    scriptBody=s["scriptBody"].encode('utf-8').strip()
                    tup=scriptName,scriptBody
                    result.append(tup)
                return result
        except Exception as e:
            self.log.error('Exception : %s' % (str(e)))
        return None

    def pushNodeExporterInfoToMonitoring(self):
        if self.kafkahost is not None:
            mon=ResourceMonitor(self.sliceId, self.cometHost, self.readToken, self.kafkaTopic,
                                kafkaHost=self.kafkahost, log=self.log)
            node_exporter_url = self.ip + ":9100"
            mon.setupMonitoring(node_exporter_url)

    def runNewScripts(self):
        scripts = self.updateScriptsFromComet()
        if scripts is None:
            return
        for s in scripts:
            script = Script(s[0], s[1])
            script.run()

    def run(self):
        while True:
            if self.stopped:
                self.log.info("hostkeyd exiting")
                return
            try:
                self.get_public_ip()
                self.log.debug('Polling')
                self.updateHostsToComet()
                self.updatePubKeysToComet()
                self.updateTokensToComet()
                self.updatePubKeysFromComet()
                self.updateHostsFromComet()
                self.updateTokensFromComet()
                self.runNewScripts()
                self.fetch_remote_public_ips()
                if self.firstRun:
                   self.pushNodeExporterInfoToMonitoring()
                self.firstRun = False
            except KeyboardInterrupt:
                self.log.error('Terminating on keyboard interrupt...')
                sys.exit(0)
            except Exception as e:
                self.log.exception(('Caught exception in daemon loop; ' +
                                    'backtrace follows.'))
                self.log.error('Exception was of type: %s' % (str(type(e))))
            time.sleep(60)

    def cleanup(self):
        if self.kafkahost is not None:
             mon=ResourceMonitor(self.sliceId, None, None, self.kafkahost, self.log)
             mon.deleteTopics()
'''
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
        '-f',
        '--cometFamily',
        dest='cometFamily',
        type = str,
        default = 'all',
        help='Comet Family Suffix'
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
    parser.add_option(
        '-t',
        '--kafkatopic',
        dest='kafkatopic',
        type=str,
        help='kafkatopic'
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

    app = HostNamePubKeyCustomizer(options.cometHost, options.sliceId, options.readToken, options.writeToken,
                                   options.id, options.kafkahost, options.kafkatopic, options.cometFamily)

    log = logging.getLogger("hostkey")

    try:

        log_format = \
            '%(asctime)s - %(name)s - {%(filename)s:%(lineno)d} - [%(threadName)s] - %(levelname)s - %(message)s'
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

        log.setLevel(log_level)

        log.addHandler(handler)
        log.propagate = False
        log.info('Logging Started')

        context = daemon.DaemonContext(pidfile=app.pidfile_path,
                                       stderr=app.stderr_path,
                                       stdin=app.stdin_path,
                                       stdout=app.stdout_path,
                                       files_preserve=handler.stream)

        log.info('Administrative operation: %s' % args[0])

        with context:
            app.run()

        log.info('Administrative after action: %s' % args[0])

        if args[0] == 'stop':
            app.cleanup()

    except Exception as e:
        log.propagate = True
        log.error('Unable to stop service; reason was: %s' % str(e))
        log.error('Exiting...')
        log.error(traceback.format_exc())
        sys.exit(1)
    sys.exit(0)
'''

def main():
    log = logging.getLogger("hostkey")
    try:
        usagestr = 'Usage: %prog start|stop|restart options'
        parser = OptionParser(usage=usagestr)
        parser.add_option(
            '-c',
            '--cometHost',
            dest='cometHost',
            type=str,
            help='Comet Host'
        )
        parser.add_option(
            '-s',
            '--sliceId',
            dest='sliceId',
            type=str,
            help='Slice Id'
        )
        parser.add_option(
            '-r',
            '--readToken',
            dest='readToken',
            type=str,
            help='Read Token'
        )
        parser.add_option(
            '-w',
            '--writeToken',
            dest='writeToken',
            type=str,
            help='Write Token'
        )
        parser.add_option(
            '-f',
            '--cometFamily',
            dest='cometFamily',
            type=str,
            default='all',
            help='Comet Family Suffix'
        )
        parser.add_option(
            '-i',
            '--id',
            dest='id',
            type=str,
            help='id'
        )
        parser.add_option(
            '-k',
            '--kafkahost',
            dest='kafkahost',
            type=str,
            help='kafkahost'
        )
        parser.add_option(
            '-t',
            '--kafkatopic',
            dest='kafkatopic',
            type=str,
            help='kafkatopic'
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

        app = HostNamePubKeyCustomizer(options.cometHost, options.sliceId, options.readToken, options.writeToken,
                                       options.id, options.kafkahost, options.kafkatopic, options.cometFamily)

        log_format = \
            '%(asctime)s - %(name)s - {%(filename)s:%(lineno)d} - [%(threadName)s] - %(levelname)s - %(message)s'
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

        log.setLevel(log_level)

        log.addHandler(handler)
        log.propagate = False

        log.info('Administrative operation: %s' % args[0])
        with GracefulInterruptHandler() as h:
            app.start()
            while True:
                time.sleep(0.0001)
                if h.interrupted:
                    app.stop()

                if args[0] == 'stop':
                    app.cleanup()

        log.info('Administrative after action: %s' % args[0])
    except Exception:
        log.propagate = True
        log.error('Unable to stop service; reason was: %s' % str(e))
        log.error('Exiting...')
        log.error(traceback.format_exc())
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
