#!/usr/bin/python

"""
RabbitMQ users
"""

import sys
import rdflib
import lib_common
import lib_credentials
from pyrabbit.api import Client
from sources_types import rabbitmq
from sources_types.rabbitmq import manager as survol_rabbitmq_manager
from sources_types.rabbitmq import user as survol_rabbitmq_user

# It uses the port of the management interface:
# In rabbitmq.config:
# {rabbitmq_management,
#  [
#   {listener, [{port,     12345},
#               {ip,       "127.0.0.1"}]}

# rabbitmq-plugins enable rabbitmq_management

def Main():

	cgiEnv = lib_common.CgiEnv()

	configNam = cgiEnv.GetId()

	nodeManager = survol_rabbitmq_manager.MakeUri(configNam)

	creds = lib_credentials.GetCredentials( "RabbitMQ", configNam )

	# cl = Client('localhost:12345', 'guest', 'guest')
	cl = Client(configNam, creds[0], creds[1])

	grph = cgiEnv.GetGraph()

	# cl.is_alive()

	#>>> cl.get_users()
	#[{u'hashing_algorithm': u'rabbit_password_hashing_sha256', u'name': u'guest', u'tags': u'administrator', u'password_hash': u'xxxxxx'}]
	try:
		#
		listUsers = cl.get_users()
	except:
		#
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:"+str(exc))

 	for objUser in listUsers:
		namUser = objUser["name"]
		sys.stderr.write("q=%s\n"%(namUser))

		nodeUser = survol_rabbitmq_user.MakeUri(configNam,namUser)

                try:
		    grph.add( ( nodeUser, lib_common.MakeProp("Tags"), rdflib.Literal(objUser["tags"]) ) )
                except KeyError:
                    pass

                try:
		    grph.add( ( nodeUser, lib_common.MakeProp("Hashing algorithm"), rdflib.Literal(objUser["hashing_algorithm"]) ) )
                except KeyError:
                    pass

		# http://127.0.0.1:12345/#/users/guest
		managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"users",namUser)

		grph.add( ( nodeUser, lib_common.MakeProp("Management"), rdflib.URIRef(managementUrl) ) )

		grph.add( ( nodeManager, lib_common.MakeProp("User"), nodeUser ) )


	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
