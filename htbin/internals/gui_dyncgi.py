#!/usr/bin/python

# Ca sert a editer un CGI, et a lui adjoindre des arguments
# pour en faire un URL. On peut stocker cet URL dans une 
# SQLite, une page de bookmarks etc...

import os
import re
import sys
import time
import subprocess
import rdflib
import urllib

# This gives the possibility to store the bookmarks the way we want.
import gui_bookmark_store

import cgi
import cgitb; cgitb.enable() # Optional; for debugging only

# This prints a Javascript array which contains all the parameters
# of the URLs. These parameters can then be edited in a HTML form.
def CgiEdit(argument):
	name = arguments.getlist("name")[0]
	url = gui_bookmark_store.BookmarkStore().JsonGet(name)
	cgivars_decoded=urllib.unquote(cgivars).decode('utf8')
	list_urls = cgivars_decoded.split('&')
	# ... to be finished ...
	# ... notably add the other arguments, for example the script.


# This receives all the arguments of an URL to create in a file or to update.
# The arguments are the name, the cgi file name and the input URLs.
def CgiCreate(arguments):
	name = arguments.getlist("name")[0]
	engine = arguments.getlist("engine")[0]
	list_args = ""
	delimiter = '?'
	for filter in arguments.getlist("url"):
		delimiter = '&'
		list_args = list_args + delimiter + "url=" + filter
	# Here we store/update a new line with this name.
	complete_url = engine + urllib.quote(list_args).encode("utf8")
	gui_bookmark_store.BookmarkStore().JsonSet(name,complete_url)
	# Back to edition and displaying of the parameters ????????? Not clear.
	# CgiEdit(arguments)
	CgiList(arguments)

def CgiDelete(arguments):
	# There might be several URLs to delete.
	names_to_delete = arguments.getlist("name")

	print "Content-type: text/html\r\n"
	print "\r\n";
	print "<html>"
	print "<header>"
	print "</header>"
	print "Deleted urls<br>";
	print "<table border=1>";

	for name in names_to_delete:
		print "<tr>";
		print "<td>" + name + "</td>";
		result = gui_bookmark_store.BookmarkStore().JsonDel(name)
		print "<td>" + result + "</td>";
		print "</tr>";
	print "</table>";
	print "<body>"
	print "</body>"
	print "</html>"
	print "\r\n"

# Only the URL name is used. It simply runs the CGI.
def CgiExecute(arguments):
	name = arguments.getlist("name")[0]
	url = gui_bookmark_store.BookmarkStore().JsonGet(name)

	print "Refresh: 0; url=" + url + "\r\n"
	print "Content-type: text/html\r\n"
	print "\r\n";
	print "Please follow the new link!"

def CgiList(arguments):
	# Ca, il faudra le changer car on va avoir une liste recursive, qu'on ne sait pas afficher.
	names_list = gui_bookmark_store.BookmarkStore().NamesList()

	print( "Content-type: text/javascript\n\n" )
	print( "var metas = " )
	# print str(names_list).encode('latin-1')
	# On a des problemes pour editer le fichier, problemes de 
	# caracteres non affichables.
	print str(names_list).encode('utf-8')
	print( ";" )

# CGI params
# url : 
# name : If empty, list all available CGIs.
# action: Create/delete/list/edit/run

# Edit doit passer par un CGI aussi car il faut aller chercher les parametres?

arguments = cgi.FieldStorage()
try:
	action = arguments.getlist("action")[0]
except KeyError:
	action = ""
except IndexError:
	action = ""

if action == "create":
	CgiCreate(arguments)
elif action == "delete":
	CgiDelete(arguments)
elif action == "edit":
	CgiEdit(arguments)
elif action == "execute":
	CgiExecute(arguments)
elif action == "list":
	CgiList(arguments)
elif action == "":
	CgiList(arguments)
else:
	print "Content-type: text/html\r\n"
	print "\r\n"
	print "Invalid action=" + str(action)

# Ce script peut etre appele a partir de plusieurs sortes de CGIs:
# - Fusion de plusieurs CGIs en entree
# - Application d'une requete SPARQL qui fait partie des arguments,
#   et on n'a en entree qu'un seul URLs.
# Ce doit etre transparent pour le script.

