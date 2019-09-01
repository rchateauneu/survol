#!/usr/bin/env python

"""
Configuration hosts
"""

import sys
import lib_common
import lib_util
import lib_uris
from sources_types.AC2 import configuration as AC2_configuration

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


def DispHosts(grph,configNode,ac2File):
	dom = AC2_configuration.GetDom(ac2File)
	for elt_hosts in dom.getElementsByTagName('hosts'):
		for elt_host in dom.getElementsByTagName('host'):
			attr_hostid = elt_host.getAttributeNode('hostid').value
			attr_host = elt_host.getAttributeNode('host').value
			attr_port = elt_host.getAttributeNode('port').value

			nodeAddr = lib_common.gUriGen.AddrUri(attr_host,attr_port)
			grph.add( ( nodeAddr, lib_common.MakeProp("Hostid"), lib_common.NodeLiteral( attr_hostid ) ) )

			grph.add( ( configNode, lib_common.MakeProp("AC2 host"), nodeAddr ) )

	return

def Main():

	cgiEnv = lib_common.CgiEnv()

	ac2File = cgiEnv.m_entity_id_dict["File"]

	DEBUG("ac2File=%s", ac2File)

	grph = cgiEnv.GetGraph()

	configNode = AC2_configuration.MakeUri(ac2File)

	DispHosts(grph,configNode,ac2File)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

