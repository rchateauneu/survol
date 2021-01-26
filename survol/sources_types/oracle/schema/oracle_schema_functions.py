#!/usr/bin/env python

"""
Oracle functions in schema
"""

import sys
import logging
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import function as oracle_function


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'FUNCTION' AND OWNER = '" + ora_schema + "'"
    logging.debug("sql_query=%s", sql_query)

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        function_name = str(row[0])
        node_function = oracle_function.MakeUri(cgiEnv.m_oraDatabase , ora_schema, function_name)
        grph.add((node_oraschema, pc.property_oracle_function, node_function))

        lib_oracle.AddLiteralNotNone(grph, node_function, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph, node_function, "Creation", row[2])

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_function])


if __name__ == '__main__':
    Main()
