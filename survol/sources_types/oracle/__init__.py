"""
Oracle concepts
"""

import lib_util

# All sub-modules in the oracle module share these graphic properties,
# unless these are superseded in the sub-modules themselves.
def Graphic_shape():
	return "none"

def Graphic_colorfill():
	return "#FFCC66"

def Graphic_colorbg():
	return "#FFCC66"

def Graphic_border():
	return 2

def Graphic_is_rounded():
	return True

# This is shared by all sub-modules.
# All subobjects have the database as first argument of their ontology.
# We do not care about the entity_host as this is simply the machine from which
# this machine was detected, so nothing more than a computer on the same network.
# It assumes that TNSADMIN file is shared by all machines.
# In reality we should fetch the IP address of the database,
# from the tnsadmin file.
def UniversalAlias(entity_ids_arr,entity_host,entity_class):
	entity_module = lib_util.GetEntityModule(entity_class)
	return entity_module.EntityName(entity_ids_arr)

# TODO: Display the processes or Oracle sessons which access a table, or any other Oracle object.

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
