# Copyright (c) 2017 Renaissance Computing Institute, except where noted.
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
# Author: Ilya Baldin (ibaldin@renci.org)
# Author: Paul Ruth (pruth@renci.org)
# Author: Victor J. Orlikowski (vjo@duke.edu)

import os
import stat
import subprocess

from host_key_tools import LOGGER, CONFIG

import logging
import logging.handlers


class Script:
    def __init__(self, name, script):
        self.log = logging.getLogger(LOGGER)
        self.log.debug('Creating NeucaScript: %s -- %s'
                       % (name, script))

        self.scriptDir = CONFIG.get('runtime', 'state-directory')
        self.name = name
        self.completed = False

        if not os.path.exists(self.scriptDir + '/' + self.name):
            fd = open(self.scriptDir + '/' + self.name, 'w')
            fd.write(script)
            fd.close()
            os.chmod(self.scriptDir + '/' + self.name, stat.S_IXUSR)
        else:
            self.completed = True

    def run(self):
        script = self.scriptDir + '/' + self.name
        output = self.scriptDir + '/' + self.name + '.log'
        if os.path.exists(output):
            self.log.info("Script already executed! Nothing to do!")
            return

        if os.path.exists(script) and not self.completed:
            try:
                self.log.info('Running: ' + script)
                with open(output,"wb") as out:
                    subprocess.Popen(['nohup', script], stdout=out, stderr=out)
                self.log.info('Running: ' + script + ' completed')
            except IOError:
                pass
            self.completed = True
