"""
Callable or data library symbol
"""

import cgi
import lib_properties
from lib_properties import pc
import lib_uris
import lib_util
import lib_common

def EntityOntology():
	return ( ["Name","File"], )

def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	try:
		# Trailing padding.
		resu = lib_util.Base64Decode(entity_id)
		# TODO: LE FAIRE AUSSI POUR LES AUTRES SYMBOLES.
		resu = cgi.escape(resu)
		return resu
	except TypeError:
		exc = sys.exc_info()[1]
		sys.stderr.write("CANNOT DECODE: symbol=(%s):%s\n"%(entity_id,str(exc)))
		return entity_id


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	# TODO: Define symbol with two different key/vals, instead of this. Bad syntax !!!
	symbole_name = entity_ids_arr[0]
	try:
		file = entity_ids_arr[1]
	except IndexError:
		file = ""

	# WRONG, TODO: Must check the node ???
	fileNode = lib_common.gUriGen.FileUri( file )
	grph.add( ( fileNode, pc.property_symbol_defined, node ) )

# This adds a function call which is modelled with a function name and a file.
# This is used with plain code and with Python.
# This should include a line number or an address.
def AddFunctionCall( grph, callNodePrev, procNode, callName, fileName, codeLocation = None ):
	if callName != None:
		callNodeNew = lib_common.gUriGen.SymbolUri( callName, fileName )
		if not callNodePrev is None:
			# Intermediary function in the callstack.
			grph.add( ( callNodeNew, pc.property_calls, callNodePrev ) )
		nodeFile = lib_common.gUriGen.FileUri( fileName )
		grph.add( ( nodeFile, pc.property_defines, callNodeNew ) )

		# This adds an address or a line number.
		# TODO: This should make the node unique, therefore a new class should be created.
		if codeLocation:
			grph.add( ( callNodeNew, lib_common.MakeProp("Code location"), lib_common.NodeLiteral(codeLocation) ) )

		return callNodeNew
	else:
		# Top-level function of the process.
		if not callNodePrev is None:
			grph.add( ( procNode, pc.property_calls, callNodePrev ) )
		return None
