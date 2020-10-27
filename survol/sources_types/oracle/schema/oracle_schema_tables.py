#!/usr/bin/env python

"""
Oracle tables
"""

import sys
import lib_common
from lib_properties import pc
import lib_oracle

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import table as oracle_table

def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'TABLE' AND OWNER = '" + ora_schema + "'"
    DEBUG("sql_query=%s", sql_query)

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)

    result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

    for row in result:
        table_name = str(row[0])
        node_table = oracle_table.MakeUri(cgiEnv.m_oraDatabase, ora_schema, table_name)
        grph.add((node_oraschema, pc.property_oracle_table, node_table))

        lib_oracle.AddLiteralNotNone(grph, node_table, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph,node_table, "Creation", row[2])

    # It cannot work if there are too many tables.
    # cgiEnv.OutCgiRdf("LAYOUT_RECT")
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_table])

if __name__ == '__main__':
    Main()
