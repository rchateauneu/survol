#!/usr/bin/env python

"""
Oracle table dependencies
"""

import re
import sys
import logging

import lib_common
from lib_properties import pc
import lib_oracle
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import table as oracle_table


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_table = cgiEnv.m_entity_id_dict["Table"]
    ora_schema = cgiEnv.m_entity_id_dict["Schema"]
    ora_database = cgiEnv.m_entity_id_dict["Db"]

    grph = cgiEnv.GetGraph()

    # TYPE = "VIEW", "TABLE", "PACKAGE BODY" etc...
    sql_query = "select owner,name,type from all_dependencies where REFERENCED_TYPE = 'TABLE' AND REFERENCED_NAME = '" \
                + ora_table + "' and referenced_owner='" + ora_schema + "'"

    logging.debug("sql_query=%s", sql_query)

    node_ora_table = oracle_table.MakeUri(ora_database, ora_schema, ora_table)

    node_ora_schema = oracle_schema.MakeUri(ora_database, ora_schema)
    grph.add((node_ora_schema, pc.property_oracle_table, node_ora_table))

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        lib_oracle.AddDependency(grph, row, node_ora_table, ora_database, True)

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()

