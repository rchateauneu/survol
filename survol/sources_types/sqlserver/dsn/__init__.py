"""
Sqlserver Data Source Name
"""

import lib_uris
import lib_common
import lib_util
from sources_types import odbc as survol_odbc
from sources_types.odbc import CgiPropertyDsn


def EntityOntology():
    return ([survol_odbc.CgiPropertyDsn()],)


def MakeUri(dsn_name):
    return lib_uris.gUriGen.node_from_dict("sqlserver/dsn", {survol_odbc.CgiPropertyDsn(): dsn_name})


# So the values of keys "PWD" and "PASSWORD" are replaced by "xxx" etc...
def EntityName(entity_ids_arr):
    return survol_odbc.CgiPropertyDsn().ValueDisplay(entity_ids_arr[0])

