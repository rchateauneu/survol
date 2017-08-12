#!/usr/bin/python

"""
Pefile exports
"""

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import sys
import time
import psutil
import lib_util
import lib_uris
import lib_common
import lib_properties
from lib_properties import pc

# This can work only on Windows and with exe files.
import pefile
import lib_pefile

Usable = lib_util.UsableWindowsBinary

def pefileDecorate( grph, rootNode, pe ):
	for fileinfo in pe.FileInfo:
		if fileinfo.Key == 'StringFileInfo':
			for st in fileinfo.StringTable:
				for entry in st.entries.items():
					#UnicodeEncodeError: 'ascii' codec can't encode character u'\xa9' in position 16: ordinal not in range(128)
					# sys.stderr.write("%s %s\n"% (entry[0], entry[1]) )
					key = entry[0]
					val = entry[1]
					if val is None:
						val = "None"
					else:
						val = val.encode("ascii", errors="replace")
						# val = val.encode("utf-8", errors="replace")
					# val = val[:2]
					# sys.stderr.write("%s %s\n"% (key,val) )
					grph.add( ( rootNode, lib_common.MakeProp(key), lib_common.NodeLiteral(val) ) )
		return


def Main():
	cgiEnv = lib_common.CgiEnv()
	filNam = cgiEnv.GetId()
	sys.stderr.write("filNam=%s\n" % filNam )

	filNode = lib_common.gUriGen.FileUri(filNam )

	try:
		pe = pefile.PE(filNam)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("File: %s. Exception:%s:" % ( filNam, str(exc)))

	# sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.Length) )
	# sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.Type) )
	# sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.ValueLength) )
	# sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.Signature) )
	# sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.FileFlags) )
	# sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.FileOS) )
	# for fileinfo in pe.FileInfo:
	# 	if fileinfo.Key == 'StringFileInfo':
	# 		for st in fileinfo.StringTable:
	# 			for entry in st.entries.items():
	# 				#UnicodeEncodeError: 'ascii' codec can't encode character u'\xa9' in position 16: ordinal not in range(128)
	# 				# sys.stderr.write("%s %s\n"% (entry[0], entry[1]) )
	# 				key = entry[0]
	# 				val = entry[1]
	# 				key = key
	# 				if val is None:
	# 					val = "None"
	# 				else:
	# 					val = val.encode("ascii", errors="replace")
	# 					# val = val.encode("utf-8", errors="replace")
	# 				# val = val[:2]
	# 				sys.stderr.write("%s %s\n"% (key,val) )
	# 	elif fileinfo.Key == 'VarFileInfo':
	# 		for var in fileinfo.Var:
	# 			sys.stderr.write('%s: %s\n' % var.entry.items()[0] )
	#


	# If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
	# pe.parse_data_directories()

	grph = cgiEnv.GetGraph()

	try:
		propForward = lib_common.MakeProp("Forward")
		propAddress = lib_common.MakeProp("Address")
		propOrdinal = lib_common.MakeProp("Ordinal")
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			# sys.stderr.write("\t%s %s %d\n"% ( hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal ) )

			decodedSymNam = lib_pefile.UndecorateSymbol(exp.name)
			symNode = lib_uris.gUriGen.SymbolUri( decodedSymNam, filNam )
			grph.add( ( filNode, pc.property_symbol_defined, symNode ) )
			forward = exp.forwarder
			if not forward:
				forward = ""
			grph.add( ( symNode, propForward, lib_common.NodeLiteral(forward) ) )
			grph.add( ( symNode, propAddress, lib_common.NodeLiteral(hex(exp.address)) ) )
			grph.add( ( symNode, propOrdinal, lib_common.NodeLiteral(hex(exp.ordinal)) ) )
			# grph.add( ( symNode, lib_common.MakeProp("Rest"), lib_common.NodeLiteral(dir(exp)) ) )
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("File: %s. Exception:%s:" % ( filNam, str(exc)))

	# cgiEnv.OutCgiRdf()
	# cgiEnv.OutCgiRdf("LAYOUT_TWOPI")
	cgiEnv.OutCgiRdf("LAYOUT_RECT",[pc.property_symbol_defined])

if __name__ == '__main__':
	Main()
