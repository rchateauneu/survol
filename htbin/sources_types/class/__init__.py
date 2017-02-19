"""
Object class as defined in a software library.
"""

import cgi
import lib_util
import sys

def EntityOntology():
	return ( ["Name","File"],)

def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	# PROBLEME: Double &kt;&lt !!!
	# return entity_id
	try:
		# Trailing padding.
		resu = lib_util.Base64Decode(entity_id)
		resu = cgi.escape(resu)
		return resu
	except TypeError:
		exc = sys.exc_info()[1]
		sys.stderr.write("CANNOT DECODE: class=(%s):%s\n"%(entity_id,str(exc)))
		return entity_id

