#!/usr/bin/env python

"""
Oracle synonyms
"""

import sys
import lib_common
from lib_properties import pc
import lib_oracle

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import synonym as oracle_synonym


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'SYNONYM' AND OWNER = '" + ora_schema + "'"
    DEBUG("sql_query=%s", sql_query)

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema )

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        synonym_name = str(row[0])
        node_synonym = oracle_synonym.MakeUri(cgiEnv.m_oraDatabase , ora_schema, synonym_name)
        grph.add((node_oraschema, pc.property_oracle_synonym, node_synonym))

        lib_oracle.AddLiteralNotNone(grph, node_synonym, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph, node_synonym, "Creation", row[2])

    # It cannot work if there are too many views.
    # cgiEnv.OutCgiRdf("LAYOUT_RECT")
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_synonym])


if __name__ == '__main__':
    Main()
