import lib_common

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
	return ( ["Name"], )

def MakeUri(groupName):
	return lib_common.gUriGen.UriMakeFromDict("Win32_Group", { "Name" : groupName } )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	groupName = entity_ids_arr[0]
	nodeGroup = lib_common.gUriGen.FileUri( groupName )
	grph.add((node,lib_common.MakeProp("Win32_Group"),nodeGroup))
