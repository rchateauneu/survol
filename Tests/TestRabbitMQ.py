# https://pyrabbit.readthedocs.io/en/latest/api.html#pyrabbit.api.Client.get_queues
#
# The default location for the real configuration file is %APPDATA%\RabbitMQ\rabbitmq.config.

import sys
from pyrabbit.api import Client

# It uses the port of the management interface:
# In rabbitmq.config:
# {rabbitmq_management,
#  [
#   {listener, [{port,     12345},
#               {ip,       "127.0.0.1"}]}

# rabbitmq-plugins enable rabbitmq_management

cl = Client('localhost:12345', 'guest', 'guest')

sys.stdout.write("\n"+"cl=%s\n"%str(cl))

isal = cl.is_alive()

sys.stdout.write("\n"+"isalive=%s\n"%str(isal))

sys.stdout.write("\n\n")

# queues = [q['name'] for q in cl.get_queues()]
queues = [q for q in cl.get_queues()]

# exclusive=False
# reductions=11223
# garbage_collection={u'min_heap_size': 233, u'fullsweep_after': 65535, u'minor_gcs': 2, u'min_bin_vheap_size': 46422}
# messages_ready_ram=0
# idle_since=2017-02-05 14:08:12
# message_bytes_unacknowledged=0
# message_stats={u'deliver_no_ack': 0, u'publish_out': 0, u'get_no_ack': 10, u'return_unroutable': 0, u'confirm': 0, u'get_no_ack_details': {u'rate': 0.0}, u'publish': 10, u'confirm_details': {u'rate': 0.0}, u'ack_details': {u'rate': 0.0}, u'get': 0, u'publish_out_details': {u'rate': 0.0}, u'deliver': 0, u'deliver_no_ack_details': {u'rate': 0.0}, u'deliver_details': {u'rate': 0.0}, u'deliver_get_details': {u'rate': 0.0}, u'publish_details': {u'rate': 0.0}, u'publish_in_details': {u'rate': 0.0}, u'ack': 0, u'publish_in': 0, u'return_unroutable_details': {u'rate': 0.0}, u'get_details': {u'rate': 0.0}, u'deliver_get': 10, u'redeliver_details': {u'rate': 0.0}, u'redeliver': 0}
# messages_unacknowledged=0
# messages_unacknowledged_ram=0
# recoverable_slaves=None
# consumers=0
# durable=False
# state=running
# message_bytes_persistent=0
# arguments={}
# memory=42440
# exclusive_consumer_tag=None
# messages_ready_details={u'rate': 0.0}
# auto_delete=False
# consumer_utilisation=None
# node=rabbit@rchateau-HP
# messages_ram=0
# message_bytes_ready=0
# head_message_timestamp=None
# messages_details={u'rate': 0.0}
# policy=None
# disk_reads=0
# message_bytes=0
# messages_unacknowledged_details={u'rate': 0.0}
# name=aliveness-test
# messages_persistent=0
# backing_queue_status={u'q1': 0, u'q3': 0, u'q2': 0, u'q4': 0, u'avg_ack_egress_rate': 0.0, u'len': 0, u'target_ram_count': u'infinity', u'mode': u'default', u'next_seq_id': 9, u'delta': [u'delta', u'undefined', 0, u'undefined'], u'avg_ack_ingress_rate': 0.0, u'avg_egress_rate': 0.027872863563508363, u'avg_ingress_rate': 0.027872863563508363}
# disk_writes=0
# messages=0
# message_bytes_ram=0
# vhost=/
# reductions_details={u'rate': 0.0}
# messages_ready=0

for qu in queues:
	sys.stdout.write("q=%s\n"%(qu["name"]))
	for k in qu:
		v = qu[k]
		sys.stdout.write("%s=%s\n"%(k,v))
