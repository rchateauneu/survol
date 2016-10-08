import re
import cgi
import lib_util
import lib_common

# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visoble as EntityName() does the reverse decoding.
def MakeUri(strQuery):
	strQueryEncoded = lib_util.Base64Encode(strQuery)
	return lib_common.gUriGen.UriMake("sql/query",strQueryEncoded)

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
def EntityName(entity_ids_arr):
	resu = lib_util.Base64Decode(entity_ids_arr[0])
	resu = cgi.escape(resu)
	resu = stripblanks(resu)
	return resu

# Eventuellement on pourrait avoir des mots-clefs indiquant le type de la base
# de donnees, son nom, les credentials etc...
# Ca permettrait de repartir des tables vers la base.