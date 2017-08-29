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
