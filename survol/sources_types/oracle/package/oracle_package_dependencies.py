#!/usr/bin/env python

"""
Oracle package dependencies
"""

import sys
import logging

from lib_properties import pc
import lib_oracle
import lib_common
from sources_types.oracle import package as oracle_package
from sources_types.oracle import schema as oracle_schema


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_package = cgiEnv.m_entity_id_dict["Package"]
    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    node_ora_package = oracle_package.MakeUri(cgiEnv.m_oraDatabase, ora_schema, ora_package)

    node_ora_schema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)
    grph.add((node_ora_schema, pc.property_oracle_package, node_ora_package))

    # TYPE = "VIEW", "TABLE", "PACKAGE BODY"
    sql_query = "select owner,name,type from dba_dependencies where REFERENCED_TYPE = 'PACKAGE' AND REFERENCED_NAME = '"\
                + ora_package + "' and referenced_owner='" + ora_schema + "'"
    logging.debug("sql_query=%s", sql_query)
    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        lib_oracle.AddDependency(grph, row, node_ora_package, cgiEnv.m_oraDatabase, True)

    sql_query_inv = "select referenced_owner,referenced_name,referenced_type from dba_dependencies where type='PACKAGE' and NAME = '"\
                    + ora_package + "' and OWNER='" + ora_schema + "'"
    logging.debug("sql_query_inv=%s", sql_query_inv)
    result_inv = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query_inv)

    for row in result_inv:
        lib_oracle.AddDependency(grph, row, node_ora_package, cgiEnv.m_oraDatabase, False)

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
