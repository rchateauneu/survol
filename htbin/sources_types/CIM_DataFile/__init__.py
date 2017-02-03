import os
import sys
import datetime
import rdflib
import lib_common
import lib_util
import lib_uris
from lib_properties import pc

def EntityOntology():
	return ( ["Name"], )

def AddMagic( grph, filNode, entity_ids_arr ):
	filNam = entity_ids_arr[0]
	try:
		import magic
	except ImportError:
		sys.stderr.write("File magic unavailable:%s\n" % (filNam) )
		return

	try:
		ms = magic.open(magic.MAGIC_NONE)
		ms.load()
		mtype =  ms.file(filNam)
		ms.close()
		grph.add( ( filNode, pc.property_information, rdflib.Literal(mtype) ) )
	except TypeError:
		sys.stderr.write("Type error:%s\n" % (filNam) )
		return

# Transforms a "stat" date into something which can be printed.
def IntToDateLiteral(timeStamp):
	dtStr = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y-%m-%d %H:%M:%S')
	return rdflib.Literal(dtStr)

# Adds to the node of a file some information taken from a call to stat().
def AddStatNode( grph, filNode, infoStat ):
	# st_size: size of file, in bytes.
	grph.add( ( filNode, pc.property_file_size, rdflib.Literal(infoStat.st_size) ) )

	grph.add( ( filNode, pc.property_last_access,          IntToDateLiteral(infoStat.st_atime) ) )
	grph.add( ( filNode, pc.property_last_change,          IntToDateLiteral(infoStat.st_mtime) ) )
	grph.add( ( filNode, pc.property_last_metadata_change, IntToDateLiteral(infoStat.st_ctime) ) )

def AddStat( grph, filNode, filNam ):
	try:
		statObj = os.stat(filNam)
		AddStatNode( grph, filNode, statObj )
	except Exception:
		# If there is an error, displays the message.
		exc = sys.exc_info()[1]
		msg = str(exc)
		grph.add( ( filNode, pc.property_information, rdflib.Literal(msg) ) )

# BEWARE: This link always as a literal. So it is simpler to display
# in an embedded HTML table.
# NON: On stocke les urls vraiment comment des URI.
def AddHtml( grph, filNode, filNam ):
	# Get the mime type, maybe with Magic. Then return a URL with for this mime type.
	# This is a separated script because it returns HTML data, not RDF.
	url_mime = lib_uris.gUriGen.FileUriMime(filNam)
	grph.add( ( filNode, pc.property_rdf_data_nolist1, rdflib.term.URIRef(url_mime) ) )

# Display the node of the directory this file is in.
def AddParentDir( grph, filNode, filNam ):
	dirPath = os.path.dirname(filNam)
	if dirPath and dirPath != filNam:
		# Possibly trunc last backslash such as in "C:\" as it crashes graphviz !
		if dirPath[-1] == "\\":
			dirPath = dirPath[:-1]
		dirNode = lib_uris.gUriGen.DirectoryUri(dirPath)
		# grph.add( ( dirNode, pc.property_directory, filNode ) )
		# We do not use the property pc.property_directory because it breaks the display.
		# Also, the direction is inverted so the current file is displayed on the left.
		grph.add( ( filNode, lib_common.MakeProp("Top directory"), dirNode ) )


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	filNam = entity_ids_arr[0]
	if filNam == "":
		return
	AddMagic( grph,node,filNam)
	AddStat( grph,node,filNam)
	AddHtml( grph,node,filNam)
	AddParentDir( grph,node,filNam)

	url_mime = lib_uris.gUriGen.FileUriMime(filNam)
	grph.add( ( node, pc.property_rdf_data_nolist1, rdflib.term.URIRef(url_mime) ) )

