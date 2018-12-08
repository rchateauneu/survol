"""
Abstract SQL query
"""

import re
import sys
import cgi
import lib_util
import lib_common

# This behaves like a string plus some properties for serialization.
class CgiPropertyB64(str):
	# Python 2
	def __new__(cls,propName):
		#obj = str.__new__(self, propName)
		#return obj
		return super(CgiPropertyB64, cls).__new__(cls, propName)

	# Python 3
	#def __new__(cls,propName):
	#	obj = str.__new__(self, propName)
	#	return obj

	#def __new__(cls, content):
	#	return super().__new__(cls, content.upper())


	def ValueEncode(self,valueClear):
		return lib_util.Base64Encode(valueClear)

	def ValueDecode(self,valueCoded):
		return lib_util.Base64Decode(valueCoded)

	def ValueDisplay(self,valueClear):
		return cgi.escape(valueClear)


class CgiPropertyQuery(CgiPropertyB64):
	#def __init__(self):
	#	#pass
	#	super(CgiPropertyQuery, self).__init__("Query")
	#	# super(CgiPropertyQuery, cls).__new__(cls, propName)

	# Python 2
	def __new__(cls):
		return super(CgiPropertyQuery, cls).__new__(cls, "Query")



# This array will be concatenated to other strings, depending of the origin of the query: database,
# process memory, file content.
def EntityOntology():
	return ( [CgiPropertyQuery(),], )

# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
# TODO: This is called from other classes like that: sql_query.MakeUri( strQuery, "oracle/query", Db = theDb )
# On voudrait davantage generaliser.
def MakeUri(strQuery,derivedEntity = "sql/query", **kwargs):
	# sys.stderr.write("derivedEntity=%s strQuery=%s kwargs=%s\n"%(derivedEntity,strQuery,str(kwargs)))
	strQueryEncoded = lib_util.Base64Encode(strQuery)
	# The result might be: { "Query" : strQueryEncoded, "Pid" : thePid  }

	# Rather CgiPropertyQuery() instead of "Query"
	allKeyedArgs = { "Query" : strQueryEncoded }
	allKeyedArgs.update( kwargs )
	# Maybe we could take the calling module as derived entity ?
	return lib_common.gUriGen.UriMakeFromDict(derivedEntity,allKeyedArgs )

def AddInfo(grph,node,entity_ids_arr):
	strQuery = entity_ids_arr[0]

# TODO: It should not strip blanks between simple-quotes.
def stripblanks(text):
	lst = text.split('"')
	for i, item in enumerate(lst):
		if not i % 2:
			lst[i] = re.sub("\s+", " ", item)
	return '"'.join(lst)

# This is dynamically called from the function EntityArrToLabel() in lib_naming.py.
# It returns a printable string, given the url arguments.T
# TODO: Problem, this is not compatible with variable arguments.
def EntityName(entity_ids_arr):
	resu = lib_util.Base64Decode(entity_ids_arr[0])
	resu = cgi.escape(resu)
	resu = stripblanks(resu)
	return resu

# This extracts the arguments from the URL. We make a function from it so that
# it wraps the decoding.
def GetEnvArgs(cgiEnv):
	sqlQuery_encode = cgiEnv.m_entity_id_dict["Query"]
	sqlQuery = lib_util.Base64Decode(sqlQuery_encode)
	return ( sqlQuery )


# Only cosmetic reasons: The displayed text should not be too long, when used as a title.
def EntityNameUtil(textPrefix,sqlQuery):
	resu = lib_util.Base64Decode(sqlQuery)
	resu = cgi.escape(resu)
	resu = stripblanks(resu)

	lenFilNam = len(textPrefix)
	lenResu = len(resu)
	lenTot = lenFilNam + lenResu
	lenMaxi = 50
	lenDiff = lenTot - lenMaxi
	if lenDiff > 0:
		lenResu -= lenDiff
		if lenResu < 30:
			lenResu = 30

		return textPrefix + ":" + resu[:lenResu] + "..."
	else:
		return textPrefix + ":" + resu
