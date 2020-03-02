#!/usr/bin/env python
import psutil
import socket
import json
from kafka import *

class ResourceMonitor():

    def __init__(self, topic, kafkaHost='localhost:9092', log=None):
        self._kafkHost = kafkaHost
        self._topic = topic
        self._log = log
        self._ssl_cafile = '/var/private/ssl/ca.crt'
        self._ssl_certfile = '/var/private/ssl/client.pem'
        self._ssl_keyfile = '/var/private/ssl/key.pem'

    def logMessage(self, message):
        if self._log is None:
            print(message)
        else:
           self._log.debug(message)

    def getResources(self):
        cpuUsage = psutil.cpu_times_percent()._asdict()
        memUsage = psutil.virtual_memory()._asdict()
        diskUsage = psutil.disk_usage("/")._asdict()
        resources = {}
        resources["idlecpu"] = cpuUsage["idle"]
        resources["memoryused"] = memUsage["percent"]
        resources["diskused"] = diskUsage["percent"]
        return (json.dumps(resources))

    def publish_message(self, producer_instance, topic_name, value):
        try:
            value_bytes = value.encode(encoding='utf-8')
            producer_instance.send(topic_name, value=value_bytes)
            producer_instance.flush()
            self.logMessage('Message published successfully.')
        except Exception as ex:
            self.logMessage('Exception in publishing message %s' % (str(type(ex))))


    def connect_kafka_producer(self, host='localhost:9092'):
        _producer = None
        try:
            if '9092' in host:
                _producer = KafkaProducer(bootstrap_servers=[host], api_version=(0, 10))
            else:
                _producer = KafkaProducer(bootstrap_servers=[host],
                                          api_version=(0, 10),
                                          security_protocol='SSL',
                                          ssl_check_hostname=False,
                                          ssl_cafile=self._ssl_cafile,
                                          ssl_certfile=self._ssl_certfile,
                                          ssl_keyfile=self._ssl_keyfile)
        except Exception as ex:
            self.logMessage('Exception while connecting Kafka %s' % (str(type(ex))))
        finally:
            return _producer

    def monitorAndSend(self):
        producer = self.connect_kafka_producer(self._kafkHost)
        if producer is not None:
            self.publish_message(producer, self._topic + socket.gethostname(), str(self.getResources()))
        else:
            self.logMessage('Unable to get a producer')

    def deleteTopics(self):
        topics = [self._topic]
        a = None
        if '9092' in host:
            a = KafkaAdminClient(bootstrap_servers=[self._kafkHost])
        else :
            a = KafkaAdminClient(bootstrap_servers=[self._kafkHost],
                                 security_protocol='SSL',
                                 ssl_check_hostname=False,
                                 ssl_cafile=self._ssl_cafile,
                                 ssl_certfile=self._ssl_certfile,
                                 ssl_keyfile=self._ssl_keyfile)
        a.delete_topics(topics, timeout_ms=30)
