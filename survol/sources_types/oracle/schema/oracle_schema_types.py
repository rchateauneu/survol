#!/usr/bin/env python

"""
Oracle types
"""

import sys
import logging
import lib_common
from lib_properties import pc
import lib_oracle

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import type as oracle_type


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'TYPE' AND OWNER = '" + ora_schema + "'"
    logging.debug("sql_query=%s", sql_query)

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        type_name = str(row[0])
        node_type = oracle_type.MakeUri(cgiEnv.m_oraDatabase , ora_schema, type_name)
        grph.add((node_oraschema, pc.property_oracle_type, node_type))

        lib_oracle.AddLiteralNotNone(grph, node_type, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph, node_type, "Creation", row[2])

    # Display in lines.
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_type])


if __name__ == '__main__':
    Main()
