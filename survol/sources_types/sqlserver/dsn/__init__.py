"""
Sqlserver Data Source Name
"""

import lib_common
import lib_util
from sources_types import odbc as survol_odbc
# Does it avoid cyclic dependencies ??
from sources_types.odbc import CgiPropertyDsn

def EntityOntology():
	return ( [survol_odbc.CgiPropertyDsn()], )

def MakeUri(dsnName):
	return lib_common.gUriGen.UriMakeFromDict("sqlserver/dsn", { survol_odbc.CgiPropertyDsn() : dsnName })

# So the values of keys "PWD" and "PASSWORD" are replaced by "xxx" etc...
def EntityName(entity_ids_arr,entity_host):
	# sys.stderr.write("EntityName entity_ids_arr=%s\n"%str(entity_ids_arr))
	return survol_odbc.CgiPropertyDsn().ValueDisplay(entity_ids_arr[0])

