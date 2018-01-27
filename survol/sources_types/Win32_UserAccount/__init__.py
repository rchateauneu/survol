"""
Scripts related to Windows Win32_UserAccount class.
"""
import lib_common
import lib_uris

def EntityOntology():
	return ( ["Name","Domain"], )

# BEWARE: Very close to lib_uris.UserUri
def MakeUri(userName,domainName):
	return lib_common.gUriGen.UriMakeFromDict("Win32_UserAccount", { "Name" : userName, "Domain" : domainName } )

def EntityName(entity_ids_arr):
	if entity_ids_arr[1]:
		return entity_ids_arr[1] + "\\\\" + entity_ids_arr[0]
	else:
		return entity_ids_arr[0]

def AddInfo(grph,node,entity_ids_arr):
	# groupName = entity_ids_arr[0]
	domainName = entity_ids_arr[1]
	nodeMachine = lib_common.gUriGen.HostnameUri( domainName )
	grph.add((node,lib_common.MakeProp("Host"), nodeMachine))