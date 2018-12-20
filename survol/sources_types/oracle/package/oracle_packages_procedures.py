#!/usr/bin/python

"""
Oracle procedures in a package
"""

import sys
import lib_common
from lib_properties import pc
import lib_oracle
from sources_types.oracle import package as oracle_package
from sources_types.oracle import schema as oracle_schema
from sources_types.oracle import procedure as oracle_procedure

def Main():
	cgiEnv = lib_oracle.OracleEnv()

	oraPackage = cgiEnv.m_entity_id_dict["Package"]
	oraSchema = cgiEnv.m_entity_id_dict["Schema"]

	grph = cgiEnv.GetGraph()

	node_oraPackage = oracle_package.MakeUri( cgiEnv.m_oraDatabase, oraSchema, oraPackage )

	node_oraSchema = oracle_schema.MakeUri( cgiEnv.m_oraDatabase, oraSchema )
	grph.add( ( node_oraSchema, pc.property_oracle_package, node_oraPackage ) )

	# TODO: This is problematic as these could also be functions.
	# TODO: But when joining with ALL_OBJECTS, most rows are gone. So what to do ?
	sql_query = "select distinct procedure_name from all_procedures where object_type='PACKAGE' " \
				"and owner='" + oraSchema + "' and object_name='" + oraPackage + "'"
	DEBUG("sql_query=%s", sql_query )
	result = lib_oracle.ExecuteQuery( cgiEnv.ConnectStr(), sql_query)

	propProcToPackage = lib_common.MakeProp("Package")
	for row in result:
		procedureName = row[0]
		procedureNode = oracle_procedure.MakeUri( cgiEnv.m_oraDatabase, oraSchema, procedureName )
		grph.add( ( node_oraPackage,propProcToPackage, procedureNode ) )


	cgiEnv.OutCgiRdf("LAYOUT_SPLINE", [propProcToPackage])

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

