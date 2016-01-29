import os
import sys
import datetime
import rdflib
import lib_common
import lib_util
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
	# Get the mime type, maybe with Magic.
	# Then return a URL with for this mime type.
	# En fait il faut juste servir le contenu du fichier, peut-etre avec le bon mime-type en effet.
	# On ne le met pas dans le directory "htbin/sources_types/file" car il ne doit pas etre tout le
	# temps liste, car il renvoie du html et pds du rdf
	url_mime = lib_util.Scriptize('/file_to_mime.py', "file", lib_util.EncodeUri(filNam) )
	grph.add( ( filNode, pc.property_html_data, rdflib.term.URIRef(url_mime) ) )

	# IMAGES DO NOT WORK YET.
	# url_icon = "http://127.0.0.1:80/PythonStyle/Icons.16x16/fileicons.chromefans.org/avi.png"
	# url_icon = "D:/Projects/Divers/Reverse/PythonStyle/Icons.16x16/fileicons.chromefans.org/avi.png"
	# url_icon = "D:/Projects/Divers/Reverse/PythonStyle/Icons.16x16/fileicons.chromefans.org/grenouille.jpg"
	# grph.add( ( filNode, pc.property_image, rdflib.term.URIRef(url_icon) ) )


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_id):
	filNam = entity_id[0]
	if filNam == "":
		return
	AddMagic( grph,node,filNam)
	AddStat( grph,node,filNam)
	AddHtml( grph,node,filNam)




