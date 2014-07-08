#!/usr/bin/python

# +------+----------------------+---------------------+----+---------+------+-------+------------------+
# | Id   | User                 | Host                | db | Command | Time | State | Info             |
# +------+----------------------+---------------------+----+---------+------+-------+------------------+
# | 1908 | unauthenticated user | 192.168.1.103:46046 |    | Connect |      | login |                  |
# | 1909 | unauthenticated user | 192.168.1.103:46047 |    | Connect |      | login |                  |
# | 1910 | unauthenticated user | 192.168.1.103:46048 |    | Connect |      | login |

# We should rather use the proper Python API to MySql but I have problems
# installing it for the moment. You get the idea, it will not change anything.

# There is no one-to-one equivalence between mysql ids and process ids,
# however, given the hosts, some association might be possible.

import os
import rdflib
import lib_common
from lib_common import pc

grph = rdflib.Graph()

mysql_cmd = "mysqladmin processlist"

for lin in os.popen(mysql_cmd):
	words_arr = lin.split('|')
	if len(words_arr) < 4:
		continue

	mysql_id = words_arr[1].strip()
	mysql_host = words_arr[3].strip()
	if mysql_host == 'Host':
		continue

	# print "Host=" + mysql_host + "."
	# print "id=" + mysql_id + "."

	mysql_addr_arr = mysql_host.split(':')
	mysql_id_node = rdflib.term.URIRef(u'urn://' + lib_common.hostName + '/mysql/' + str(mysql_id) )
	if len(mysql_addr_arr) == 2:
		socketNode = lib_common.AddrUri( mysql_addr_arr[0], mysql_addr_arr[1] )
		grph.add( ( mysql_id_node, pc.property_has_socket_end, socketNode ) )
		# TODO: Here, we should create a dummy socket and a dummy process id on the other machine.
		# Otherwise, the merging will not bring anything.
	else:
		dummy_local_process = lib_common.AnonymousPidNode(lib_common.hostName)
		grph.add( ( dummy_local_process, pc.property_mysql_id, mysql_id_node ) )



	#except psutil._error.AccessDenied:
	#	pass
	#except psutil._error.NoSuchProcess:
	#	pass
	#except:
	#	print "Unexpected error:", sys.exc_info()[0]
	#	raise


lib_common.OutCgiRdf(grph)


