#!/usr/bin/python

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import sys
import time
import rdflib
import psutil
import json
import lib_entities.lib_entity_file
import lib_util
import lib_common
import lib_properties
from lib_properties import pc

# This can work only on Windows and with exe files.
try:
	import pefile
except ImportError:
	lib_common.ErrorMessageHtml("Module pefile should be installed")


def pefileDecorate( grph, rootNode, pe ):
	for fileinfo in pe.FileInfo:
		if fileinfo.Key == 'StringFileInfo':
			for st in fileinfo.StringTable:
				for entry in st.entries.items():
					#UnicodeEncodeError: 'ascii' codec can't encode character u'\xa9' in position 16: ordinal not in range(128)
					# sys.stderr.write("%s %s\n"% (entry[0], entry[1]) )
					key = entry[0]
					val = entry[1]
					key = key
					if val is None:
						val = "None"
					else:
						val = val.encode("ascii", errors="replace")
						# val = val.encode("utf-8", errors="replace")
					# val = val[:2]
					sys.stderr.write("%s %s\n"% (key,val) )
					grph.add( ( rootNode, lib_common.MakeProp(key), rdflib.Literal(val) ) )
		return


def Main():
	cgiEnv = lib_common.CgiEnv("Pefile information")
	filNam = cgiEnv.GetId()
	sys.stderr.write("filNam=%s\n" % filNam )

	filNode = lib_common.gUriGen.FileUri(filNam )

	pe = pefile.PE(filNam)

	sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.Length) )
	sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.Type) )
	sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.ValueLength) )
	sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.Signature) )
	sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.FileFlags) )
	sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.FileOS) )
	for fileinfo in pe.FileInfo:
		if fileinfo.Key == 'StringFileInfo':
			for st in fileinfo.StringTable:
				for entry in st.entries.items():
					#UnicodeEncodeError: 'ascii' codec can't encode character u'\xa9' in position 16: ordinal not in range(128)
					# sys.stderr.write("%s %s\n"% (entry[0], entry[1]) )
					key = entry[0]
					val = entry[1]
					key = key
					if val is None:
						val = "None"
					else:
						val = val.encode("ascii", errors="replace")
						# val = val.encode("utf-8", errors="replace")
					# val = val[:2]
					sys.stderr.write("%s %s\n"% (key,val) )
		elif fileinfo.Key == 'VarFileInfo':
			for var in fileinfo.Var:
				sys.stderr.write('%s: %s\n' % var.entry.items()[0] )



	# If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
	pe.parse_data_directories()

	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		sys.stderr.write("dll=%s\n"%entry.dll)
		for imp in entry.imports:
			sys.stderr.write("\t%s %s\n"% (hex(imp.address), imp.name) )


	sys.stderr.write("Exports:\n")
	for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
		sys.stderr.write("\t%s %s %d\n"% ( hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal ) )

	grph = rdflib.Graph()


	cgiEnv.OutCgiRdf(grph)
	# cgiEnv.OutCgiRdf(grph,"LAYOUT_TWOPI")

if __name__ == '__main__':
	Main()
