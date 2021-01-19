#!/usr/bin/env python

"""
Oracle packages
"""

import sys
import logging
from lib_properties import pc
import lib_oracle
import lib_common

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import package as oracle_package


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    # BEWARE: There is an implicit dependency on the structure of Oracle schema URI.
    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'PACKAGE' AND OWNER = '" + ora_schema + "'"
    logging.debug("sql_query=%s", sql_query )

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        package_name = str(row[0])
        # sys.stderr.write("tableName=%s\n" % tableName )
        node_package = oracle_package.MakeUri(cgiEnv.m_oraDatabase, ora_schema, package_name)
        grph.add((node_oraschema, pc.property_oracle_package, node_package))

        lib_oracle.AddLiteralNotNone(grph, node_package, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph, node_package, "Creation", row[2])

    # It cannot work if there are too many tables.
    # cgiEnv.OutCgiRdf("LAYOUT_RECT")
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_package])


if __name__ == '__main__':
    Main()
