# host-key-tools
python daemon to exchange hostnames and keys across nodes configured on COMET

This software is intented to be install on VMs or Baremetal server for which a COMET context has been created.
This software configures hostnames in /etc/hosts and shares publick keys between all the nodes configured in COMET context for the server.

## Install host-key-tools
```
python setup.py install
```

## Usage
```
Usage: hostkey.py start|stop|restart options

Options:
  -h, --help            show this help message and exit
  -c COMETHOST, --cometHost=COMETHOST
                        Comet Host
  -s SLICEID, --sliceId=SLICEID
                        Slice Id
  -r READTOKEN, --readToken=READTOKEN
                        Read Token
  -w WRITETOKEN, --writeToken=WRITETOKEN
                        Write Token
  -i ID, --id=ID        id
```

## Verify hostkey daemon is running
```
ps -eaf | grep hostkeyd 
root 11133 1 2 14:12 ? 00:00:00 python /usr/bin/hostkeyd start
```

