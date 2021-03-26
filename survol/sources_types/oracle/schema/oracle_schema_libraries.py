#!/usr/bin/env python

"""
Oracle libraries in schema
"""

import sys
import logging

from lib_properties import pc
import lib_oracle
import lib_common
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import library as oracle_library

def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'LIBRARY' AND OWNER = '" + \
                ora_schema + "'"
    logging.debug("sql_query=%s", sql_query)

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        library_name = str(row[0])
        node_library = oracle_library.MakeUri(cgiEnv.m_oraDatabase, ora_schema, library_name)
        grph.add((node_oraschema, pc.property_oracle_library, node_library))

        lib_oracle.AddLiteralNotNone(grph, node_library, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph, node_library, "Creation", row[2])

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_library])


if __name__ == '__main__':
    Main()
