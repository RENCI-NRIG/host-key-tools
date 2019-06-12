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
import tempfile

from host_key_tools import LOGGER

import logging
import logging.handlers

from subprocess import Popen, PIPE, STDOUT

from os import kill
from signal import alarm, signal, SIGALRM, SIGKILL


class TempFile(file):
    """Copyright (c) 2010 Alon Swartz <alon@turnkeylinux.org> -
    All Rights Reserved"""

    def __init__(self, prefix='tmp', suffix=''):
        fd, path = tempfile.mkstemp(suffix, prefix)
        os.close(fd)
        self.path = path
        self.pid = os.getpid()
        file.__init__(self, path, 'w')

    def __del__(self):
        if self.pid == os.getpid():
            os.remove(self.path)


class Commands:
    @classmethod
    def run_cmd(self, args):
        cmd = args
        log = logging.getLogger(LOGGER)
        log.debug('running command: ' + ' '.join(cmd))
        p = Popen(cmd, stdout=PIPE, stderr=STDOUT)
        retval = p.communicate()[0]
        return retval

    @classmethod
    def run(self,
            args,
            cwd=None,
            shell=False,
            kill_tree=True,
            timeout=-1,
            env=None):
        '''
        Run a command with a timeout after which it will be forcibly
        killed.

        Mostly from Alex Martelli solution (probably from one of his
        python books) posted on stackoverflow.com
        '''

        class Alarm(Exception):
            pass

        def alarm_handler(signum, frame):
            raise Alarm

        log = logging.getLogger(LOGGER)
        log.debug('run: args= ' + str(args))
        # p = Popen(args, shell=shell, cwd=cwd,
        #           stdout=PIPE, stderr=PIPE, env=env)
        p = Popen(args, stdout=PIPE, stderr=STDOUT)
        if timeout != -1:
            signal(SIGALRM, alarm_handler)
            alarm(timeout)
        try:
            stdout, stderr = p.communicate()
            if timeout != -1:
                alarm(0)
        except Alarm:
            pids = [p.pid]
            if kill_tree:
                pids.extend(self._get_process_children(p.pid))
            for pid in pids:
                # process might have died before getting to this line
                # so wrap to avoid OSError: no such process
                try:
                    kill(pid, SIGKILL)
                except OSError:
                    pass
            return -9, '', ''
        return p.returncode, stdout, stderr

    @classmethod
    def _get_process_children(self, pid):
        p = Popen(
            'ps --no-headers -o pid --ppid %d' % pid,
            shell=True,
            stdout=PIPE,
            stderr=PIPE)
        stdout, stderr = p.communicate()
        return [int(i) for i in stdout.split()]

    @classmethod
    def source(self, script, update=1):
        pipe = Popen(
            '. %s; env' % script,
            stdout=PIPE,
            shell=True,
            env={'PATH': os.environ['PATH']})
        data = pipe.communicate()[0]
        env = dict((line.split('=', 1) for line in data.splitlines()))
        if update:
            os.environ.update(env)
        return env
