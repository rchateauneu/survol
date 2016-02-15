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
import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("mysql sessions","http://www.mysql.fr/common/logos/powered-by-mysql-88x31.png")

grph = rdflib.Graph()

mysql_cmd = "mysqladmin processlist"

try:
	mysql_resu = os.popen(mysql_cmd)
except FileNotFoundError:
	lib_common.ErrorMessageHtml("Cannot find mysqladmin")

for lin in mysql_resu:
	sys.stderr.write("lin="+lin+"\n")
	words_arr = lin.split('|')
	if len(words_arr) < 4:
		continue

	mysql_id = words_arr[1].strip()
	# This is a MySql user, not Linux or Windows.
	mysql_user = words_arr[2].strip()
	mysql_host = words_arr[3].strip()
	mysql_command = words_arr[8].strip()
	if mysql_host == 'Host':
		continue
	sys.stderr.write("host="+mysql_host+"\n")

	mysql_addr_arr = mysql_host.split(':')
	mysql_id_node = rdflib.term.URIRef('urn://' + lib_util.currentHostname + '/mysql/' + str(mysql_id) )
	if len(mysql_addr_arr) == 2:
		socketNode = lib_common.gUriGen.AddrUri( mysql_addr_arr[0], mysql_addr_arr[1] )
		# BEWARE: mysql_id_node is not a process. But why not after all.
		grph.add( ( mysql_id_node, pc.property_has_socket, socketNode ) )
		# TODO: Here, we should create a dummy socket and a dummy process id on the other machine.
		# Otherwise, the merging will not bring anything.
		sql_task_node = socketNode

	else:
		dummy_local_process = lib_common.AnonymousPidNode(lib_util.currentHostname)
		grph.add( ( dummy_local_process, pc.property_mysql_id, mysql_id_node ) )
		sql_task_node = dummy_local_process

	if mysql_command != "":
		grph.add( ( sql_task_node, pc.property_information, rdflib.Literal(mysql_command) ) )


# Ce lien est en principe toujours valable.
# Mais idealement il faudrait le tester.
# TODO: CHECK IF THIS IS THE RIGHT PORT NUMBER.

phpmyadminUrl = "http://" + lib_util.currentHostname + "/phpmyadmin/"
phpmyadminNode = rdflib.term.URIRef( phpmyadminUrl )
grph.add( ( lib_common.nodeMachine, pc.property_html_data, phpmyadminNode ) )

cgiEnv.OutCgiRdf(grph)

# Il faudrait renvoyer vers le site http://localhost/phpmyadmin/ quand on examine 

