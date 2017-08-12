#!/usr/bin/python

"""
Installed RPMs
"""

import rpm
import sys
import socket
import rdflib
from rdflib.namespace import XSD
import lib_util
import lib_common
from lib_properties import pc

from sources_types import rpm as survol_rpm

#http://stackoverflow.com/questions/34360353/how-to-get-list-installed-linux-rpms-with-python
#
#import rpm
#
#ts = rpm.TransactionSet()
#mi = ts.dbMatch()
#for h in mi:
#    print "%s-%s-%s" % (h['name'], h['version'], h['release'])

#xcb-util-keysyms-0.4.0-1.fc22
#device-mapper-event-1.02.93-3.fc22
#mesa-dri-drivers-10.6.3-1.20150729.fc22


# No need of a Usable() function because the only condition is to have the rpm package installed.


def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	rpmProps = survol_rpm.RpmProps()

	rpmPropName = lib_common.MakeProp("rpm")

	try:
		ts = rpm.TransactionSet()
		mi = ts.dbMatch()
		for h in mi:
			rpmName = h['name']

			nodeRpm = survol_rpm.MakeUri(rpmName)
			# Unfortunately, it does not seem to work to force the type.
			# TODO: Maybe this is because we later try to convert to a number,
			# without checking the type of the data ???
			for propKey in rpmProps:
				propRpm = rpmProps[propKey]
				# The value might be None.
				propVal = h[ propKey ] or ""
				grph.add( ( nodeRpm, propRpm, lib_common.NodeLiteral(propVal, datatype=XSD.string) ) )

			grph.add( ( lib_common.nodeMachine, rpmPropName, nodeRpm ) )
	except Exception:
		lib_common.ErrorMessageHtml("List of RPMs: Error %s" % ( str( sys.exc_info() ) ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT", [rpmPropName])

if __name__ == '__main__':
	Main()
