#!/usr/bin/env python
import psutil
import socket
import json
from kafka import *
from ssl import create_default_context, Purpose

def _create_ssl_context(*, cafile=None, capath=None, cadata=None,
                       certfile=None, keyfile=None, password=None,
                       crlfile=None):
    """
    Simple helper, that creates an SSLContext based on params similar to
    those in ``kafka-python``, but with some restrictions like:

            * ``check_hostname`` is not optional, and will be set to True
            * ``crlfile`` option is missing. It is fairly hard to test it.

    .. _load_verify_locations: https://docs.python.org/3/library/ssl.html\
        #ssl.SSLContext.load_verify_locations
    .. _load_cert_chain: https://docs.python.org/3/library/ssl.html\
        #ssl.SSLContext.load_cert_chain

    Arguments:
        cafile (str): Certificate Authority file path containing certificates
            used to sign broker certificates. If CA not specified (by either
            cafile, capath, cadata) default system CA will be used if found by
            OpenSSL. For more information see `load_verify_locations`_.
            Default: None
        capath (str): Same as `cafile`, but points to a directory containing
            several CA certificates. For more information see
            `load_verify_locations`_. Default: None
        cadata (str/bytes): Same as `cafile`, but instead contains already
            read data in either ASCII or bytes format. Can be used to specify
            DER-encoded certificates, rather than PEM ones. For more
            information see `load_verify_locations`_. Default: None
        certfile (str): optional filename of file in PEM format containing
            the client certificate, as well as any CA certificates needed to
            establish the certificate's authenticity. For more information see
            `load_cert_chain`_. Default: None.
        keyfile (str): optional filename containing the client private key.
            For more information see `load_cert_chain`_. Default: None.
        password (str): optional password to be used when loading the
            certificate chain. For more information see `load_cert_chain`_.
            Default: None.

    """
    if cafile or capath:
        print('Loading SSL CA from %s', cafile or capath)
    elif cadata is not None:
        print('Loading SSL CA from data provided in `cadata`')
        print('`cadata`: %r', cadata)
    # Creating context with default params for client sockets.
    context = create_default_context(
        Purpose.SERVER_AUTH, cafile=cafile, capath=capath, cadata=cadata)
    # Load certificate if one is specified.
    if certfile is not None:
        print('Loading SSL Cert from %s', certfile)
        if keyfile:
            if password is not None:
                print('Loading SSL Key from %s with password', keyfile)
            else:  # pragma: no cover
                print('Loading SSL Key from %s without password', keyfile)
        # NOTE: From docs:
        # If the password argument is not specified and a password is required,
        # OpenSSLs built-in password prompting mechanism will be used to
        # interactively prompt the user for a password.
        context.load_cert_chain(certfile, keyfile, password)
    return context


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
                context = self._create_ssl()
                _producer = KafkaProducer(bootstrap_servers=[host],
                                          api_version=(0, 10),
                                          security_protocol='SSL',
                                          ssl_context=context)
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
        if '9092' in self._kafkHost:
            a = KafkaAdminClient(bootstrap_servers=[self._kafkHost])
        else :
            context = self._create_ssl()
            a = KafkaAdminClient(bootstrap_servers=[self._kafkHost],
                                 security_protocol='SSL',
                                 ssl_context=context)
        a.delete_topics(topics, timeout_ms=30)

    def _create_ssl(self):
        context = _create_ssl_context(
            cafile=self._ssl_cafile,  # CA used to sign certificate.
            # `CARoot` of JKS store container
            certfile=self._ssl_certfile,  # Signed certificate
            keyfile=self._ssl_keyfile,  # Private Key file of `certfile` certificate
        )

        context.check_hostname = False
        context.verify_mode = False
        return context
