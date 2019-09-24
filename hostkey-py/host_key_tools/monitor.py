#!/usr/bin/env python
import psutil
import socket
from kafka import KafkaProducer

class ResourceMonitor():

    def __init__(self, topic, kafkaHost='localhost:9092', log=None):
        self._kafkHost = kafkaHost
        self._topic = topic
        self._log = log

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
        resources["cpu"] = cpuUsage
        resources["memory"] = memUsage
        resources["disk"] = diskUsage
        return (resources)

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
            _producer = KafkaProducer(bootstrap_servers=[host], api_version=(0, 10))
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
