#!/usr/bin/python

"""
Dumpbin symbols associated to a DLL
"""

import os
import subprocess
import re
import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

# Trouver un moyen de passer un parametre a un cgi :
# - Creer des URL qu on injecte dans un fichier dot.
#   Ca exige une passe speciale qui va reconnaitre la nature des noeuds.
# - Sur un SVG donne, il faut pouvoir developper plusieurs noeuds 
#   (c est-a-dire merger avec des urls contenant ce noeud comme parametre).
# - Peut-etre style de merge ou, pour chaque noeud d un type donne, 
#   on charge un pattern d URL en ajoutant ce noeud comme parameter. 
#   Peut-etre pratique mais on risque d avoir un graphe enorme. Pas incompatible avec le reste.
# - Quand on cliquerait un node, ca rappellerait le meme URL mais en ajoutant comme nouvel argument CGI, 
#   l URL implicitement cree en cliquant ce noeud (Ou check-box auquel cas on retire le parametre 
#   (En fait un URL) de la liste d url parametres CGI. 
#   On peut faire ca plus facilement si on affiche un url sous forme d une liste de triplets, 
#   avec une check-box pour chaque triplet (Signifiant : " expansion pour un type d URL 
#   admettant ce type de noeud comme parametre)
# - Comment qualifier dynamiquement, qu un URL doit prendre comme parametre un noeud d un type donne ? 
#   Aussi, ca implique que le nom d un noeud le qualifie entierement : On peut aller chercher un fichier, 
#   voir un process sur une machine donnee etc
#   Eventuellement, cet identifiant unique est affiche sous forme de raccourci.
# - Retour sur les points d entree dans les DLL/so : 
#   On parle bien d un point d entree dans une DLL donnee : 
#   Pas forcement, c est une abstraction. 
#   En revanche, permettre d instrumenter la combinaison : symbole+fichier.

def Usable(entity_type,entity_ids_arr):
	"""Not a Windows binary or executable file"""
	if not lib_util.UsableWindows(entity_type,entity_ids_arr):
		return False
	fulFileName = entity_ids_arr[0]
	filename, file_extension = os.path.splitext(fulFileName)
	return file_extension.upper() in [".EXE", ".DLL", ".COM", ".OCX", ".SYS", ".ACM", ".BPL", ".DPL"]

def Main():
	cgiEnv = lib_common.CgiEnv()
	dll_file = cgiEnv.GetId()

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("DLL files are on Windows platforms only")

	# This should be a parameter.
	dumpbin_exe = "\"c:/Program Files (x86)/Microsoft Visual Studio 10.0/VC/bin/amd64/dumpbin.exe\""
	# dumpbin_exe = "dumpbin.exe"
	# dll_file = "C:/Program Files (x86)/IBM/WebSphere MQ/bin/amqmdnet.dll"
	dumpbin_cmd = [ dumpbin_exe, dll_file, "/exports" ]

	try:
		dumpbin_pipe = subprocess.Popen(dumpbin_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	except WindowsError:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Windows error executing:"+" ".join(dumpbin_cmd)+":"+str(exc))
		# TODO: "Access is denied". Why ???

	( dumpbin_out, dumpbin_err ) = dumpbin_pipe.communicate()

	err_asstr = dumpbin_err.decode("utf-8")
	err_lines = err_asstr.split('\n')

	lib_common.ErrorMessageHtml("Err="+str(err_lines))

	# Converts to string for Python3.
	out_asstr = dumpbin_out.decode("utf-8")
	out_lines = out_asstr.split('\n')

	grph = rdflib.Graph()

	nodeDLL = lib_common.gUriGen.FileUri( dll_file )

	for lin in out_lines:
		#        362  168 0111B5D0 ?CompareNoCase@AString@ole@@QBEHPBD@Z = ?CompareNoCase@AString@ole@@QBEHPBD@Z (public: int __thiscall ole:
		matchObj = re.match( r'^ *[0-9A-F]+ *[0-9A-F]+ *[0-9A-F]+ ([^ ]+) = ([^ ]+)', lin )
		if matchObj:
			sym = matchObj.group(1)
			# TODO: Not sure about the file.
			nodeSymbol = lib_common.gUriGen.SymbolUri(sym, dll_file)
			grph.add( ( nodeDLL, pc.property_symbol_defined, nodeSymbol ) )
			# print( "OK :" + matchObj.group(1) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
