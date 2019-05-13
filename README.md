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
[root@master0 system]# ps -eaf | grep python
root      1663     1  0 18:32 ?        00:00:01 python /usr/bin/hostkeyd start -c https://18.221.238.74:8111/ -s abcd-5678 -r abcd-5678read -w abcd-5678write -i master0
```

