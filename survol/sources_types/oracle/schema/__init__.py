"""
Oracle database schema
"""

import lib_common
from lib_properties import pc
from sources_types.oracle import db as oracle_db

def Graphic_colorbg():
	return "#CC99FF"

def EntityOntology():
	return ( ["Db", "Schema"], )

# Beware of the possible confusion with normal users.
def MakeUri(dbName,schemaName):
	return lib_common.gUriGen.UriMakeFromDict("oracle/schema", { "Db" : dbName, "Schema" : schemaName } )

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dbNam = entity_ids_arr[0]
	nodeDb = oracle_db.MakeUri(dbNam)

	grph.add( ( nodeDb, pc.property_oracle_schema, node ) )

def EntityName(entity_ids_arr):
	return entity_ids_arr[0] + "." + entity_ids_arr[1]

# SQL> select distinct object_type from dba_objects;
#
# CLUSTER
# CONSUMER GROUP
# CONTEXT
# DATABASE LINK
# DESTINATION
# DIRECTORY
# EDITION
# EVALUATION CONTEXT
# FUNCTION
# INDEX
# INDEX PARTITION
# INDEXTYPE
# JOB
# JOB CLASS
# LIBRARY
# LOB
# LOB PARTITION
# OPERATOR
# PACKAGE
# PACKAGE BODY
# PROCEDURE
# PROGRAM
# QUEUE
# RESOURCE PLAN
# RULE
# RULE SET
# SCHEDULE
# SCHEDULER GROUP
# SEQUENCE
# SYNONYM
# TABLE
# TABLE PARTITION
# TABLE SUBPARTITION
# TRIGGER
# TYPE
# TYPE BODY
# UNDEFINED
# VIEW
# WINDOW
# XML SCHEMA
