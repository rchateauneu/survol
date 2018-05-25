"""
Extraction of SQL queries from process memory.
"""

from sources_types.sql import query as sql_query

import lib_util

# Explanation about the object model:
# A directory defines a class if the __init__.py object contains a function named EntityOntology().
# Otherwise, it is a subclass of the parent directory. If no EntityOntology() function is defined
# in none of the parent directories, then it is a static class or a namespace.

# The result should be ["Query","Handle"]
# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
	# return ( sql_query.EntityOntology() + lib_util.OntologyClassKeys("CIM_Process") )
	return ( ["Query","Handle"],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(strQuery,thePid):
	#strQueryEncoded = lib_util.Base64Encode(strQuery)
	# TODO: We have hard-coded the process definition with "Handle".
	# TODO: The entity parameter should be passed differently, more elegant. Not sure.
	#return lib_common.gUriGen.UriMakeFromDict("sql/query",{ "Query" : strQueryEncoded, "Handle" : thePid })
	# return sql_query.MakeUri( strQuery, "CIM_Process/embedded_sql_query", { "Handle" : thePid } )
	return sql_query.MakeUri( strQuery, "CIM_Process/embedded_sql_query", Handle = thePid )

def AddInfo(grph,node,entity_ids_arr):
	strQuery = entity_ids_arr[0]
	pid = entity_ids_arr[1]

def EntityName(entity_ids_arr):
	thePid = entity_ids_arr[1]
	# sys.stderr.write("thePid=%s\n"%thePid)
	sqlQuery = entity_ids_arr[0]
	resu = lib_util.Base64Decode(sqlQuery)

	# If the query contains double-quotes, it crashes Graphviz
	resu = resu.replace('"',"'")
	# resu = resu.replace('"','\\"')
	return "Pid " + str(thePid) + ":" + resu
	# return resu
