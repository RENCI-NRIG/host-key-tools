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
import json
import sys
import logging
import time
from logging.handlers import RotatingFileHandler
import traceback

from optparse import OptionParser

from .comet_common_iface import CometInterface
from .monitor import ResourceMonitor
from .script import Script
from . import LOGGER, CONFIG
from .daemon import Daemon
from .graceful_interrupt_handler import GracefulInterruptHandler


class HostNamePubKeyCustomizer(Daemon):
    def __init__(self, cometHost: str, sliceId: str, readToken: str,
                 writeToken: str, rId, kafkahost: str, kafkaTopic: str, family: str, public: bool = True):
        super().__init__()
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
        self.local_ip = None
        self.ip = None
        self.hostsFile = '/etc/hosts'
        self.keysFile = '/root/.ssh/authorized_keys'
        self.publicKey = '/root/.ssh/id_rsa.pub'
        self.privateKey = '/root/.ssh/id_rsa'
        self.neucaPubKeysStr = ('NEuca comet pubkeys modifications - '
                                'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        self.neucaUserKeysStr = ('NEuca comet user keys modifications - '
                                 'DO NOT EDIT BETWEEN THESE LINES. ###\n')
        self.stateDir = '/var/lib/hostkey'
        self.public_ips = f"{self.stateDir}/public.json"
        self.kafkahost = kafkahost
        self.kafkaTopic = kafkaTopic
        self.public = public

        self.log = self.make_logger()

        # Need to ensure that the state directory is created.
        if not os.path.exists(self.stateDir):
            os.makedirs(self.stateDir)

    @staticmethod
    def make_logger() -> logging.Logger:
        """
        Detects the path and level for the log file from the config and sets
        up a logger.

       :return: logging.Logger object
        """
        log_file = CONFIG.get("logging", "log-file")
        log_directory = CONFIG.get("logging", "log-directory")
        log_path = f"{log_directory}/{log_file}"

        if log_path is None:
            raise RuntimeError('The log file path must be specified in config')

        # Get the log level
        log_level = CONFIG.get("logging", "log-level")

        if log_level is None:
            log_level = logging.INFO

        # Set up the root logger
        log = logging.getLogger(LOGGER)
        log.setLevel(log_level)
        log_format = \
            '%(asctime)s - %(name)s - {%(filename)s:%(lineno)d} - [%(threadName)s] - %(levelname)s - %(message)s'

        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        backup_count = CONFIG.get("logging", "log-retain")
        max_log_size = CONFIG.get("logging", "log-file-size")

        file_handler = RotatingFileHandler(log_path, backupCount=int(backup_count), maxBytes=int(max_log_size))

        logging.basicConfig(handlers=[file_handler], format=log_format)

        return log

    def stop(self):
        """
        Stop the daemon
        """
        self.cleanup()
        super().stop()

    def get_private_ip(self):
        try:
            cmd = ["/usr/bin/curl", "-s", "http://169.254.169.254/latest/meta-data/local-ipv4"]
            completed_process = subprocess.run(cmd, capture_output=True)
            ip = completed_process.stdout.strip()
            self.local_ip = str(ip, 'utf-8').strip()
            self.log.debug(f"Self Private IP: {self.local_ip}")
        except Exception as e:
            self.log.error(f'Failed to obtain public ip using command: {e}')
            self.log.error(traceback.format_exc())

    def get_public_ip(self):
        try:
            cmd = ["/usr/bin/curl", "-s", "http://169.254.169.254/latest/meta-data/public-ipv4"]
            completed_process = subprocess.run(cmd, capture_output=True)
            ip = completed_process.stdout.strip()
            self.ip = str(ip, 'utf-8').strip()
            self.log.debug(f"Self Public IP: {self.ip}")
        except Exception as e:
            self.log.error(f'Failed to obtain public ip using command: {e}')
            self.log.error(traceback.format_exc())

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
            stdout_str = str(stdout.read(), 'utf-8').strip()
            self.log.debug(f"Public IP for host: {host} {stdout_str}")
            client.close()
            return stdout_str
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
                    self.log.debug(f"h[ip]={h['ip']} ip={self.ip}")
                    if h["hostName"].replace('/','-') == self.hostName and (h["ip"] == "" or h["ip"] is None):
                    #if h["hostName"].replace('/','-') == self.hostName and h["ip"] != self.ip :
                         if self.public:
                             h["ip"] = self.ip
                         else:
                             h["ip"] = self.local_ip
                         checker = True
                if checker:
                    val = {}
                    val["val_"] = json.dumps(hosts)
                    newVal = json.dumps(val)
                    self.log.debug("Updating " + section + "=" + newVal)
                    resp = comet.invokeRoundRobinApi('update_family', self.sliceId, self.rId, self.readToken,
                                                     self.writeToken, section, json.loads(newVal))
                    if resp.status_code != 200:
                        self.log.debug("Failure occurred in updating hosts to comet" + section)
                else:
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
        ret_val = False 
        if self.kafkahost is not None and self.ip is not None:
            mon=ResourceMonitor(self.sliceId, self.cometHost, self.readToken, self.kafkaTopic,
                                kafkaHost=self.kafkahost, log=self.log)
            node_exporter_url = self.ip + ":9100"
            ret_val = mon.setupMonitoring(node_exporter_url)
        return ret_val
        

    def runNewScripts(self):
        scripts = self.updateScriptsFromComet()
        if scripts is None:
            return
        for s in scripts:
            script = Script(s[0], s[1])
            script.run()

    def run(self):
        try:
            self.get_public_ip()
            self.get_private_ip()
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
                if self.pushNodeExporterInfoToMonitoring():
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
             mon = ResourceMonitor(self.sliceId, None, None, self.kafkahost, self.log)
             mon.deleteTopics()


def setup_parser():
    usage_str = f"Usage: {sys.argv[0]} (start|stop|restart|status|reload|version)"

    parser = OptionParser(usage=usage_str)
    parser.add_option('-c', '--cometHost', dest='cometHost', type=str, help='Comet Host')
    parser.add_option('-s', '--sliceId', dest='sliceId', type=str, help='Slice Id')
    parser.add_option('-r', '--readToken', dest='readToken', type=str, help='Read Token')
    parser.add_option('-w', '--writeToken', dest='writeToken', type=str, help='Write Token')
    parser.add_option('-f', '--cometFamily', dest='cometFamily', type=str, default='all', help='Comet Family Suffix')
    parser.add_option('-i', '--id', dest='id', type=str, help='id')
    parser.add_option('-k', '--kafkahost', dest='kafkahost', type=str, help='kafkahost')
    parser.add_option('-t', '--kafkatopic', dest='kafkatopic', type=str, help='kafkatopic')
    parser.add_option('-p', '--public', dest='public', type=str, help='True for Public IP and False for Private IP', default='True')

    return parser


def main():
    parser = setup_parser()
    options, args = parser.parse_args()
    public = True
    if options.public != 'True':
         public = False

    daemon = HostNamePubKeyCustomizer(options.cometHost, options.sliceId, options.readToken, options.writeToken,
                                      options.id, options.kafkahost, options.kafkatopic, options.cometFamily, public)

    log = daemon.make_logger()

    if len(sys.argv) >= 2:
        choice = sys.argv[1]
        if choice == "start":
            log.info('Administrative operation: START')
            daemon.start()
            with GracefulInterruptHandler() as h:
                while True:
                    time.sleep(10)
                    if h.interrupted:
                        daemon.stop()
        elif choice == "stop":
            log.info('Administrative operation: STOP')
            daemon.stop()
        elif choice == "restart":
            daemon.restart()
        elif choice == "status":
            daemon.status()
        elif choice == "reload":
            daemon.reload()
        elif choice == "version":
            daemon.version()
        else:
            print("Unknown command.")
            parser.print_usage()
            sys.exit(1)
        sys.exit(0)
    else:
        parser.print_usage()
        sys.exit(1)

