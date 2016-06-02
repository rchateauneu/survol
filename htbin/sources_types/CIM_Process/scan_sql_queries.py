#!/usr/bin/python

"""
Scan SQL queries
"""

import sys
import psutil
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
from lib_properties import pc

def Usable(entity_type,entity_ids_arr):
	"""Not implemented yet"""
	return False

def Main():
	cgiEnv = lib_common.CgiEnv()
	try:
		the_pid = int( cgiEnv.GetId() )
	except Exception:
		lib_common.ErrorMessageHtml("Must provide a pid")

	grph = rdflib.Graph()

	proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(the_pid)
	procNode = lib_common.gUriGen.PidUri( the_pid )
	lib_entity_CIM_Process.AddInfo( grph, procNode, [ str(the_pid) ] )


"""
Scanner la memoire pour chercher des requetes SQL.
Mais de quelle BDD ? Oracle ? Odbc ? Sqlite ?
Utiliser Sqlparse ?
Successfully installed sqlparse-0.1.19

On ne cherche pas seulement dans le heap mais aussi dans la memoire
des constantes. Ou alors dans le exe et les dlls ? Autant chercher dans la memoire.
Il peut y avoir des %s dans les chaines.
Peut-etre simplement rechercher les chaines de caracteres et filtrer ensuite.

On peut connaitre la base de donnees en cherchant a quoi on est linke.
Ou eventuellement en cherchant des chaines particulieres,
Voir ctypes_scanner.py
"""



	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

