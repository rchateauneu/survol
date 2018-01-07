"""
Browse neighborhood services and agents
"""

import re
import sys
import lib_common

# There is no WMI neighborhood because all Windows machine have WMI.

# Typical configuration in slp.reg file.
#
# service:wbem:http://rchateau-hp,en,65535
# description=OpenPegasus sous Windows 7
#
# # Definitions must be separated by an empty line.
# service:survol:http://rchateau-hp:8000/survol/entity.py,en,65535
# description=Survol Windows 7
#
# $ slptool findsrvtypes
# service:wbem:http
# service:survol:http
#
# $ slptool findsrvs service:survol
# service:survol:http://rchateau-hp:8000/survol/entity.py,65535
#
# $ slptool findattrs service:wbem:http://rchateau-hp
# (description=OpenPegasus sous Windows 7)
# (description=OpenPegasus sous Windows 7)
# (description=OpenPegasus sous Windows 7)
#

# It could probably use the Python3 module pyslp.

# This returns a map containing the key-value pairs of the attributes
# of this service.
def GetSLPAttributes(serviceName,slpHost):
	dictAttributes = {}

	cmdSlpFindAttrs = ["slptool", 'findattrs', 'service:%s:%s' %( serviceName, slpHost) , ]

	resuFindAttrs = lib_common.SubProcPOpen(cmdSlpFindAttrs)

	(outStreamFindAttrs, errStreamFindAttrs) = resuFindAttrs.communicate()

	splitResuFindAttrs = outStreamFindAttrs.split("\n")

	for linResuFindAttrs in splitResuFindAttrs:
		sys.stderr.write("GetSLPAttributes slpHost=%s linResuFindAttrs=%s\n"%(slpHost,linResuFindAttrs))
		# service:survol:http://rchateau-hp:8000/survol/entity.py,65535
		# service:wbem:http://rchateau-hp,65535
		mtchFindAttrs = re.match( r'\(([^=]*)=([^)]*)\)', linResuFindAttrs )
		if mtchFindAttrs:
			slpAttrKey = mtchFindAttrs.group(1)
			slpAttrVal = mtchFindAttrs.group(2)
			dictAttributes[slpAttrKey] = slpAttrVal
		else:
			sys.stderr.write("No match for attributes:%s\n"%linResuFindAttrs)

	return dictAttributes

def GetSLPServices(serviceName):
	dictServices = {}

	cmdSlpTool = ["slptool", 'findsrvs', 'service:' + serviceName, ]

	resuPOpen = lib_common.SubProcPOpen(cmdSlpTool)

	(outStreamSlpTool, errStreamSlpTool) = resuPOpen.communicate()

	splitResuSlpTool = outStreamSlpTool.split("\n")

	for linResuSlpTool in splitResuSlpTool:
		sys.stderr.write("GetSLPServices serviceName=%s linResuSlpTool=%s\n"%(serviceName,linResuSlpTool))
		# service:survol:http://rchateau-hp:8000/survol/entity.py,65535
		# service:wbem:http://rchateau-hp,65535
		mtchSplTool = re.match( r'service:[^:]*:([^,]*)(.*)', linResuSlpTool )
		if mtchSplTool:
			slpHost = mtchSplTool.group(1)
			slpAttrs = GetSLPAttributes(serviceName,slpHost)
			dictServices[slpHost] = slpAttrs
		else:
			sys.stderr.write("No match:%s\n"%linResuSlpTool)

	return dictServices
