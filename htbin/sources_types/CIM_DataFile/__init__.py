import os
import sys
import datetime
import rdflib
import lib_common
import lib_util
import lib_uris
from lib_properties import pc

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

def IntToDateLiteral(timeStamp):
	dtStr = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y-%m-%d %H:%M:%S')
	return rdflib.Literal(dtStr)

def AddStatNode( grph, filNode, info ):
	# st_size: size of file, in bytes.
	grph.add( ( filNode, pc.property_file_size, rdflib.Literal(info.st_size) ) )

	grph.add( ( filNode, pc.property_last_access,          IntToDateLiteral(info.st_atime) ) )
	grph.add( ( filNode, pc.property_last_change,          IntToDateLiteral(info.st_mtime) ) )
	grph.add( ( filNode, pc.property_last_metadata_change, IntToDateLiteral(info.st_ctime) ) )

def AddStat( grph, filNode, filNam ):
	statObj = None
	try:
		statObj = os.stat(filNam)
	except Exception:
		exc = sys.exc_info()[1]
		msg = str(exc)

	# If there is an error, displays the message.
	if statObj == None:
		grph.add( ( filNode, pc.property_information, rdflib.Literal(msg) ) )
	else:
		AddStatNode( grph, filNode, statObj )

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

