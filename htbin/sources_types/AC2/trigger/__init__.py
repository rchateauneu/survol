"""
AC2 trigger
"""

import lib_common

def EntityOntology():
	return ( ["File","CronId","Trigger"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,cronId,triggerName):
	return lib_common.gUriGen.UriMakeFromDict("AC2/trigger", { "File" : configFilename, "CronId":cronId,"Trigger":triggerName } )

