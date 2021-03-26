"""
Oracle database schema
"""

import lib_uris
import lib_common

from lib_properties import pc
from sources_types.oracle import db as oracle_db


def Graphic_colorbg():
    return "#CC99FF"


def EntityOntology():
    return (["Db", "Schema"],)


# Beware of the possible confusion with normal users.
def MakeUri(db_name, schema_name):
    return lib_uris.gUriGen.UriMakeFromDict("oracle/schema", {"Db" : db_name, "Schema": schema_name})


def AddInfo(grph, node, entity_ids_arr):
    db_nam = entity_ids_arr[0]
    node_db = oracle_db.MakeUri(db_nam)

    grph.add((node_db, pc.property_oracle_schema, node))


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
