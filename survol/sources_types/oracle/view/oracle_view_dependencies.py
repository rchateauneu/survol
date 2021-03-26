#!/usr/bin/env python

"""
Oracle view dependencies
"""

import re
import sys
import logging

import lib_common
from lib_properties import pc
import lib_oracle
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import view as oracle_view


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_view = cgiEnv.m_entity_id_dict["View"]
    ora_schema = cgiEnv.m_entity_id_dict["Schema"]
    ora_database = cgiEnv.m_entity_id_dict["Db"]

    grph = cgiEnv.GetGraph()

    node_ora_view = oracle_view.MakeUri(ora_database, ora_schema, ora_view)

    node_ora_schema = oracle_schema.MakeUri(ora_database, ora_schema)
    grph.add((node_ora_schema, pc.property_oracle_view, node_ora_view))

    # TYPE = "VIEW", "TABLE", "PACKAGE BODY"
    sql_query = "select owner,name,type from all_dependencies where REFERENCED_TYPE = 'VIEW' AND REFERENCED_NAME = '" \
              + ora_view + "' and referenced_owner='" + ora_schema + "'"
    logging.debug("sql_query=%s", sql_query)
    result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

    for row in result:
        lib_oracle.AddDependency(grph, row, node_ora_view, ora_database, True)

    sql_query_inv = "select referenced_owner,referenced_name,referenced_type from all_dependencies where type='VIEW' and NAME = '" + ora_view + "' and OWNER='" + ora_schema + "'"
    logging.debug("sql_query_inv=%s", sql_query_inv)
    result_inv = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query_inv)

    for row in result_inv:
        lib_oracle.AddDependency(grph, row, node_ora_view, ora_database, False)

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()

