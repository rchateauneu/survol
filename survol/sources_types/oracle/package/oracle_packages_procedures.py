#!/usr/bin/env python

"""
Oracle procedures in a package
"""

import sys
import logging

import lib_common
from lib_properties import pc
import lib_oracle
from sources_types.oracle import package as oracle_package
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import procedure as oracle_procedure

def Main():
    cgiEnv = lib_oracle.OracleEnv()

    ora_package = cgiEnv.m_entity_id_dict["Package"]
    ora_schema = cgiEnv.m_entity_id_dict["Schema"]

    grph = cgiEnv.GetGraph()

    node_ora_package = oracle_package.MakeUri(cgiEnv.m_oraDatabase, ora_schema, ora_package)

    node_ora_schema = oracle_schema.MakeUri(cgiEnv.m_oraDatabase, ora_schema)
    grph.add((node_ora_schema, pc.property_oracle_package, node_ora_package))

    # TODO: This is problematic as these could also be functions.
    # TODO: But when joining with ALL_OBJECTS, most rows are gone. So what to do ?
    sql_query = "select distinct procedure_name from all_procedures where object_type='PACKAGE' " \
                "and owner='" + ora_schema + "' and object_name='" + ora_package + "'"
    logging.debug("sql_query=%s", sql_query)
    result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

    prop_proc_to_package = lib_common.MakeProp("Package")
    for row in result:
        procedure_name = row[0]
        procedure_node = oracle_procedure.MakeUri(cgiEnv.m_oraDatabase, ora_schema, procedure_name)
        grph.add((node_ora_package,prop_proc_to_package, procedure_node))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE", [prop_proc_to_package])


if __name__ == '__main__':
    Main()

#select object_name from all_procedures
#where owner = 'SYS' and ojbect_type='PACKAGE'

#SQL> select distinct object_type from all_procedures;
#PROCEDURE
#PACKAGE
#TRIGGER
#FUNCTION
#TYPE


#SQL> select ap.owner,ap.object_name,ap.procedure_name,ap.object_type  from all_procedures ap,all_objects ao where ap.procedure_name=
#ao.object_name and ao.object_type='FUNCTION' and ap.owner=ao.owner;
#
#SQL> select ap.owner,ap.object_name,ap.procedure_name,ap.object_type  from all_procedures ap,all_objects ao where ap.procedure_name=
#ao.object_name and ao.object_type='PROCEDURE' and ap.owner=ao.owner;

