"""
Windows group
"""

import sys
import lib_common
from lib_properties import pc

# NetGroupEnum
# NetGroupGetInfo
# NetGroupGetUsers
# NetLocalGroupEnum

# dict = NetLocalGroupGetInfo(server, groupname , level )
# >>> win32net.NetLocalGroupGetInfo(None,"Administrators",1)
# {'comment': u'Administrators have complete and unrestricted access to the computer/domain', 'name': u'Administrators'}

# ([dict, ...], total, resumeHandle) = NetLocalGroupGetMembers(server, groupName , level , resumeHandle , prefLen )
#>>> win32net.NetLocalGroupGetMembers(None,"Administrators",2,0)
#([{'sidusage': 1L, 'domainandname': u'rchateau-HP\\Administrator', 'sid': <PySID object at 0x00000000024C8D30>}, {'sidusage': 1L, 'domainandname': u'rchateau-HP\\rchateau', 'sid': <PySID object at 0x00000000024C8D70>}], 2, 0)


def EntityOntology():
	return ( ["Name","Domain"], )

def MakeUri(groupName,domainName):
	if domainName is None:
		domainName = ""
	return lib_common.gUriGen.UriMakeFromDict("Win32_Group", { "Name" : groupName, "Domain" : domainName } )

def EntityName(entity_ids_arr):
	if entity_ids_arr[1]:
		return entity_ids_arr[1] + "\\\\" + entity_ids_arr[0]
	else:
		return entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	groupName = entity_ids_arr[0]
	# sys.stderr.write("Win32_Group.AddInfo entity_ids_arr=%s\n"%str(entity_ids_arr))
	domainName = entity_ids_arr[1]

	try:
		import win32net

		dataGroup = win32net.NetLocalGroupGetInfo(None,groupName,1)
		commentGroup = dataGroup['comment']
		grph.add((node,pc.property_information, lib_common.NodeLiteral(commentGroup)))
	except:
		# Maybe this module cannot be imported.
		pass

	if domainName != "NT SERVICE":
		nodeMachine = lib_common.gUriGen.HostnameUri( domainName )
		grph.add((node,lib_common.MakeProp("Host"), nodeMachine))
