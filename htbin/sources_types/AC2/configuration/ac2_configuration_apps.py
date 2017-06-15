#!/usr/bin/python

"""
Configuration applications
"""

import sys
import rdflib
import lib_common
import lib_util
import lib_uris
from sources_types.AC2 import configuration as AC2_configuration
from sources_types.AC2 import application as AC2_application

# <?xml version="1.0" encoding="utf-8" standalone="yes"?>
# <apps>
#    <crontable>
#        <cronrules cronid="AC2-App-Sample-A scheduling">
#            <trigger name="CRON#1"
#                     action="stop"
#                     force="true"
#                     components="A1"
#                     propagate="false"
#                     expression="0 00 * * * ? *"/>
#            <trigger name="CRON#3" action="stop" expression="0 30 * * * ? *"/>
#        </cronrules>
#    </crontable>
#     <hosts>
#         <host hostid="LOCAL"
#               host="127.0.0.1"
#               port="12567"/>
#     </hosts>
#     <app name="AC2-App-Sample-A"
#          version="Version-1"
#          notifref="AC2-App-Sample-A notification rule"
#          cronref="AC2-App-Sample-A scheduling">
def DispApp(grph,configNode,configName):
	dom = AC2_configuration.GetDom(configName)
	for elt_app in dom.getElementsByTagName('app'):
		attr_name = elt_app.getAttributeNode('name').value
		attr_version = elt_app.getAttributeNode('version').value
		attr_notifref = elt_app.getAttributeNode('notifref').value
		attr_cronref = elt_app.getAttributeNode('cronref').value

		nodeApp = AC2_application.MakeUri(configName,attr_name)
		grph.add( ( nodeApp, lib_common.MakeProp("version"), rdflib.Literal( attr_version ) ) )
		grph.add( ( nodeApp, lib_common.MakeProp("notifref"), rdflib.Literal( attr_notifref ) ) )
		grph.add( ( nodeApp, lib_common.MakeProp("cronref"), rdflib.Literal( attr_cronref ) ) )

		grph.add( ( configNode, lib_common.MakeProp("AC2 application"), nodeApp ) )


	return

def Main():

	cgiEnv = lib_common.CgiEnv()

	ac2File = cgiEnv.m_entity_id_dict["File"]

	sys.stderr.write("ac2File=%s\n"% (ac2File) )

	grph = cgiEnv.GetGraph()

	configNode = AC2_configuration.MakeUri(ac2File)

	DispApp(grph,configNode,ac2File)

	# cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT", [pc.property_argument] )
	cgiEnv.OutCgiRdf(grph )

if __name__ == '__main__':
	Main()

