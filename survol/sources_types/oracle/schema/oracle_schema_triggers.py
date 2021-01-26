#!/usr/bin/env python

"""
Oracle triggers
"""

import sys
import logging
import lib_common
from lib_properties import pc
import lib_oracle

from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import trigger as oracle_trigger


def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    sql_query = "SELECT OBJECT_NAME,STATUS,CREATED FROM ALL_OBJECTS WHERE OBJECT_TYPE = 'TRIGGER' AND OWNER = '" + ora_schema + "'"
    logging.debug("sql_query=%s", sql_query)

    node_oraschema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema )

    result = lib_oracle.ExecuteQuery(cgiEnv.ConnectStr(), sql_query)

    for row in result:
        trigger_name = str(row[0])
        node_trigger = oracle_trigger.MakeUri(cgiEnv.m_oraDatabase , ora_schema, trigger_name)
        grph.add((node_oraschema, pc.property_oracle_trigger, node_trigger))

        lib_oracle.AddLiteralNotNone(grph, node_trigger, "Status", row[1])
        lib_oracle.AddLiteralNotNone(grph, node_trigger, "Creation", row[2])

    # It cannot work if there are too many views.
    # cgiEnv.OutCgiRdf("LAYOUT_RECT")
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_oracle_trigger])


if __name__ == '__main__':
    Main()
