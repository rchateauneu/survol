"""
Cron rules
"""

import lib_common

def EntityOntology():
	return ( ["File","CronId"], )

# Ambiguity with tables, oracle or normal users.
def MakeUri(configFilename,cronId):
	return lib_common.gUriGen.UriMakeFromDict("AC2/cronrules", { "File" : configFilename, "CronId":cronId } )

