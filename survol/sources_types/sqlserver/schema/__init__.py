# This is the definition of a Sql server schema.

import lib_common
import lib_uris
from sources_types.sqlserver import dsn as sqlserver_dsn


def AddInfo(grph, node, entity_ids_arr):
    dsn_nam = entity_ids_arr[0]
    node_dsn = sqlserver_dsn.MakeUri(dsn_nam)

    grph.add((node_dsn, lib_common.MakeProp("Sqlserver DSN"), node))


def EntityOntology():
    # TODO: Replace this first property by a plain string.
    # This was an attempt to solve the problem of non-printable values of properties.
    # The idea was to do this encoding only for specivif properties.
    # The information about this encoding was described by using a derived class of string.
    # But this is not compatible with CIM because attributes must be strig.
    # This must be replaced by an option B64 encoding: Such encoded string have a special prefix.
    # This can be done in any context.
    return ([sqlserver_dsn.CgiPropertyDsn(), "Schema"],)


# Beware of the possible confusion with normal users.
def MakeUri(dsn_name, schema_name):
    return lib_uris.gUriGen.UriMakeFromDict("sqlserver/schema", {sqlserver_dsn.CgiPropertyDsn(): dsn_name, "Schema": schema_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0] + "." + entity_ids_arr[1]

