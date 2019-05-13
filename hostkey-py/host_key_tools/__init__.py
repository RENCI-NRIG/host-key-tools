__version__ = '1.0'

import platform
import ConfigParser

_distro = platform.dist()[0]

_ConfDir = '/etc/hostkey'
_ConfFile = 'config'

_StateDir = '/var/lib/hostkey'
_PidDir = '/var/run'
_PidFile = 'hostkeyd.pid'

_LogDir = '/var/log/hostkey'
_LogFile = 'hostkey-agent.log'
_LogLevel = 'DEBUG'
_LogRetain = '5'
_LogFileSize = '5000000'

_CommandTimeout = '300'
_PidFileTimeout = '5'

LOGGER = 'host_key_tools_logger'

CONFIG = ConfigParser.SafeConfigParser()
CONFIG.add_section('runtime')
CONFIG.add_section('logging')
CONFIG.add_section('linux')
CONFIG.set('runtime', 'dataplane-macs-to-ignore', '')
CONFIG.set('runtime', 'state-directory', _StateDir)
CONFIG.set('runtime', 'pid-directory', _PidDir)
CONFIG.set('runtime', 'pid-file', _PidFile)
CONFIG.set('runtime', 'command-timeout', _CommandTimeout)
CONFIG.set('runtime', 'pidfile-timeout', _PidFileTimeout)
CONFIG.set('logging', 'log-directory', _LogDir)
CONFIG.set('logging', 'log-file', _LogFile)
CONFIG.set('logging', 'log-level', _LogLevel)
CONFIG.set('logging', 'log-retain', _LogRetain)
CONFIG.set('logging', 'log-file-size', _LogFileSize)
