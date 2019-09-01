#!/usr/bin/env python


"""
mysql sessions
"""

# Note: There is no space between the option "-p" and the password.
# https://stackoverflow.com/questions/12665522/is-there-a-way-to-pass-the-db-user-password-into-the-command-line-tool-mysqladmi
#
# C:\Users\rchateau>mysqladmin -u MyUser -pMyPassword processlist
# mysqladmin: [Warning] Using a password on the command line interface can be insecure.
# +------+----------------------+---------------------+----+---------+------+-------+------------------+
# | Id   | User                 | Host                | db | Command | Time | State | Info             |
# +------+----------------------+---------------------+----+---------+------+-------+------------------+
# | 1908 | unauthenticated user | 192.168.1.103:46046 |    | Connect |      | login |                  |
# | 1909 | unauthenticated user | 192.168.1.103:46047 |    | Connect |      | login |                  |
# | 1910 | unauthenticated user | 192.168.1.103:46048 |    | Connect |      | login |
#
# C:\Users\rchateau>mysqladmin -u usrXYZ -ppwdXYZ processlist -hvps516494.ovh.net
# mysqladmin: [Warning] Using a password on the command line interface can be insecure.
# +------+--------+---------------------------------------------------------+----+---------+------+-------+------------------+---------+
# | Id   | User   | Host                                                    | db | Command | Time | State | Info             | Progres |
# +------+--------+---------------------------------------------------------+----+---------+------+-------+------------------+---------+
# | 2198 | myuser | cpc85870-haye24-2-0-cust62.17-4.cable.virginm.net:59826 |    | Query   | 0    | init  | show processlist | 0.000  |
# +------+--------+---------------------------------------------------------+----+---------+------+-------+------------------+---------+

# We could also use the Python API to MySql. This solution requires less installation.

# There is no one-to-one equivalence between mysql ids and process ids,
# however, given the hosts, some association might be possible.

import os
import subprocess
import sys
import lib_util
import lib_common
from lib_properties import pc
import lib_credentials

# This does not import genuine mysql packages so this will always work.
from sources_types.mysql import instance as survol_mysql_instance

def AddMySqlPort(grph,instanceMySql):

	# Maybe there is a port number.
	hostMySql = instanceMySql.split(":")[0]

	# TODO: Display the connection socket ?
	nodeHostMySql = lib_common.gUriGen.HostnameUri( hostMySql )

	nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)

	aCred = lib_credentials.GetCredentials( "MySql", instanceMySql )

	grph.add( ( nodeInstance, lib_common.MakeProp("Mysql user"), lib_common.NodeLiteral(aCred[0]) ) )
	grph.add( ( nodeInstance, lib_common.MakeProp("Mysql instance"), nodeHostMySql ) )

	mysql_cmd_lst = ["mysqladmin","-u",aCred[0],"-p%s"%aCred[1],"-h%s"%hostMySql,"processlist"]
	mysql_cmd = " ".join(mysql_cmd_lst)
	DEBUG("mysql_cmd=%s",mysql_cmd)

	command = subprocess.Popen(mysql_cmd_lst, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	(cmd_output, cmd_error) = command.communicate()
	DEBUG("mysql_cmd cmd_error=%s",cmd_error)

	# [Warning] Using a password on the command line interface can be insecure.
	if cmd_error and cmd_error.find(""):
		lib_common.ErrorMessageHtml("Error running mysqladmin:"+ cmd_error)

	for linSql in cmd_output.split("\n"):
		DEBUG("linSql="+linSql)
		words_arr = linSql.split('|')
		if len(words_arr) < 4:
			continue

		mysql_id = words_arr[1].strip()
		# This is a MySql user, not Linux or Windows.
		mysql_user = words_arr[2].strip()
		# Should be the same as hostMySql ?
		mysql_host = words_arr[3].strip()
		mysql_command = words_arr[8].strip()
		if mysql_host == 'Host':
			continue
		DEBUG("host="+mysql_host)

		mysql_addr_arr = mysql_host.split(':')
		mysql_id_node = lib_common.NodeUrl('urn://' + mysql_host + '/mysql/' + str(mysql_id) )
		if len(mysql_addr_arr) == 2:
			socketNode = lib_common.gUriGen.AddrUri( mysql_addr_arr[0], mysql_addr_arr[1] )
			# BEWARE: mysql_id_node is not a process. But why not after all.
			grph.add( ( mysql_id_node, pc.property_has_socket, socketNode ) )
			# TODO: Here, we should create a dummy socket and a dummy process id on the other machine.
			# Otherwise, the merging will not bring anything.
			sql_task_node = socketNode

		grph.add( ( sql_task_node, lib_common.MakeProp("Mysql user"), lib_common.NodeLiteral(mysql_user) ) )

		# TODO: Add a specific node for the SQL query.
		if mysql_command != "":
			grph.add( ( sql_task_node, pc.property_information, lib_common.NodeLiteral(mysql_command) ) )

		grph.add( ( nodeInstance, lib_common.MakeProp("Mysql session"), sql_task_node ) )

	# phpmyadminUrl = "http://" + lib_util.currentHostname + "/phpmyadmin/"
	# TODO: Is this the right port number ?
	phpmyadminUrl = "http://" + hostMySql + "/phpmyadmin/"
	phpmyadminNode = lib_common.NodeUrl( phpmyadminUrl )
	return phpmyadminNode


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	credNames = lib_credentials.GetCredentialsNames( "MySql" )

	for instanceMySql in credNames:
		DEBUG("MySql servers instanceMySql=%s",instanceMySql)

		phpmyadminNode = AddMySqlPort(grph,instanceMySql)
		grph.add( ( lib_common.nodeMachine, pc.property_rdf_data_nolist1, phpmyadminNode ) )


	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

