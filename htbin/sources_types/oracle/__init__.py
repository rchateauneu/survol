import lib_credentials

# "Oracle": {
#		"XE" : [ "system", "xxx" ]
#	},
def DatabaseEnvParams(processId):
	# This is a list of db names, such as ["XE"]
	lstCredNams = lib_credentials.GetCredentialsNames('Oracle')

	# TODO: We could use the process id to check if the process executable is linked
	# with the Oracle shareable library. If not, return None.

	# Each of these elements allows to connect to an Oracle database.
	listArgs = ( { "Db" : db } for db in lstCredNams )

	return ( "oracle/query", listArgs )
