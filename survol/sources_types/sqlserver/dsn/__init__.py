"""
Sqlserver Data Source Name
"""

import lib_uris
import lib_common
import lib_util
from sources_types import odbc as survol_odbc


def EntityOntology():
    return (["Dsn"],)


def MakeUri(dsn_name):
    return lib_uris.gUriGen.node_from_dict("sqlserver/dsn", {"Dsn": dsn_name})


# So the values of keys "PWD" and "PASSWORD" are replaced by "xxx" etc...
def EntityName(entity_ids_arr):
    return survol_odbc.ShortenDsn(entity_ids_arr[0])

