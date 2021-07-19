# host-key-tools
Mobius Host Key Tools is a python daemon which supports following functionality:
- Pushes the node IP and Public Key to COMET
- Polls the IPs and Public Keys of other nodes belonging to the same group as the node from COMET
- Configures it's own /etc/hosts and /root/.ssh/authorized_keys
- Pushes Nodes Public IP and Port on which Node Exporter is running to Mobius Monitoring Server via Kafka

## Requirements
```
Kafka-python
requests
paramiko
psutil
```
## Install host-key-tools
```
git clone https://github.com/RENCI-NRIG/host-key-tools.git 
cd host-key-tools/hostkey-py/
pip3.9 install -r requirements.txt
python3.9 setup.py install
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
  -k kafkahost, --kafkahost=kafkahost
                        kafkahost
  -t kafkatopic, --kafkatopic=kafkatopic
                        kafkatopic
```

## Verify hostkey daemon is running
```
[root@master0 system]# ps -eaf | grep python
root      1663     1  0 18:32 ?        00:00:01 python /usr/bin/hostkeyd start -c https://18.221.238.74:8111/ -s abcd-5678 -r abcd-5678read -w abcd-5678write -i master0
```

