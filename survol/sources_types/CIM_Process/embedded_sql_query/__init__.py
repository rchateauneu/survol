"""
Extraction of SQL queries from process memory.
"""

from sources_types.sql import query as sql_query
# from sources_types import CIM_Process

import lib_util
# import lib_common

# TODO: What is annoying in this model is, sometimes directories have their own ontology,
# TODO: and sometimes not. What is the rule ? There is no rule, except that: Objects
# TODO: are what is instantiated with a path of subdirectories.
# TODO: GROS PROBLEME, RELIE AU SIMILI-HERITAGE DE "oracle/query"
# ou "CIM_Process/embedded_sql_query" vers "sql/query".
# TODO: Ici, quand entity.py liste les scripts, il suppose qu'ils peuvent tous
# TODO: s appliquer aux parametres courants.
# TODO: Devrait-on verifier si __init__.py contient la fonction EntityOntology() ?
# TODO: Ca voudrait dire que chaque script herite du EntityOntology() du niveau au-dessus.
# TODO: En effet, on a suppose que chaque dossier de "sources_types" est associe a un type.
# TODO: Or on a fait le contraire avec "sources_types/oracle" et "sources_types/sqlserver"
# TODO: qui justement ne sont pas des types.
# TODO: Donc en tout logique on devrait mettre tous les dossiers de "sources_types" dans "sources_top"
# TODO: ... etc et le dossier "Databases/oracle_tnsnames.py" serait dans "Databases/oracle/oracle_tnsnames.py".
# TODO: Le gros probleme est que entity.py devra scanner beaucoup plus de fichiers.
# TODO: Toutefois il s arrete d explorer des qu il rencontre un module qui contient "EntityOntology()"
# TODO: Impact: * Implementer EntityOntology() pour tout le monde.
# TODO:           Il faut le faire de toute facon.
# TODO:         * Remplacer "sources_types" par "sources_top".
# TODO:         * entity.py arrete lexploration des qu un module contient la fonction EntityOntology()
# TODO:           => On va etre oblige de le faire a cause de CIM_Process/embedded_sql_query.
# Notre modele est un peu du Duck typing de modules.as

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
