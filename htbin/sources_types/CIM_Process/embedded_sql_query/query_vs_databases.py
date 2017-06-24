#!/usr/bin/python

"""
SQL query checked against available databases.
"""

import sys
import lib_common
import lib_util
from sources_types.sql import query as sql_query
from sources_types.CIM_Process import embedded_sql_query
import lib_sql



def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	sqlQuery = sql_query.GetEnvArgs(cgiEnv)

	# TODO: It would be nicer to use a new function CIM_Process.GetEnvArgs. Not urgent.
	processId = cgiEnv.m_entity_id_dict["Handle"]

	nodeProcessQuery = embedded_sql_query.MakeUri(sqlQuery,processId)

	list_of_tables = lib_sql.TableDependencies(sqlQuery)

	propTypeDb = lib_common.MakeProp("Database type")

	arrProps = []

	# "oracle", "sqlserver", "sqlite" etc ...
	for namDbType in lib_sql.listModulesUsingSqlQueries :
		sys.stderr.write("namDbType=%s\n"%namDbType)
		# TODO: We should check if the syntax of the query is conformant to the database.
		# TODO: We should check if the process is linked with this database.

		# This creates a non-clickable node. TODO: DOES NOT WORK ??
		nodeTypeDb = lib_util.DirDocNode("sources_types",namDbType)

		propTypeThisDb = lib_common.MakeProp(namDbType)
		arrProps.append(propTypeThisDb)

		grph.add((nodeProcessQuery,propTypeDb,nodeTypeDb))
		try:

			# Now transforms the list of tables or views into nodes for this database.
			moduleDbType = lib_util.GetEntityModule(namDbType)
			if not moduleDbType:
				continue

			try:
				# This returns the possible database credentials for this database type.
				# This returns also a module name. Maybe a schema, in the future.
				# "oracle.DatabaseEnvParams()" defined in "oracle/__init__.py"
				dbTp_envParams = moduleDbType.DatabaseEnvParams(processId)
			except AttributeError:
				exc = sys.exc_info()[1]
				# Maybe the function is not defined in this module or other error.
				sys.stderr.write("Caught: %s\n"%str())
				continue

			if not dbTp_envParams:
				continue

			queryEntity = dbTp_envParams[0]
			listArgs = dbTp_envParams[1]

			# For example ( "oracle/query", ( { "Db":"XE" } ) )
			for connectionKW in listArgs:
				sys.stderr.write("connectionKW=%s\n"%connectionKW)

				moduleQueryEntity = lib_util.GetEntityModule(queryEntity)
				if not moduleQueryEntity:
					# Should not happen, otherwise how can we get the parameters for this ?
					continue

				try:
					# HELAS ON FAIT LE TRAVAIL DEUX FOIS, DE TESTER SI LES SHEETS SONT DES TABLES OU DES VIEWS.
					# Il faudrait un mode degrade ou on ne fait que tester.
					# "oracle.query.QueryToNodesList()" defined in "oracle/query/__init__.py"
					listTableNodes = moduleQueryEntity.QueryToNodesList(sqlQuery,connectionKW,list_of_tables)
				except Exception:
					continue

				if not listTableNodes:
					continue

				# We know this is a valid query for this connection, so we add a link to it.
				# Dans le lien on devra retester si vraiment valide.
				# C est la ou on voit qu il vaudrait mieux avoir des dict.
				nodeDbQuery = sql_query.MakeUri(sqlQuery,queryEntity,**connectionKW)

				grph.add((nodeTypeDb,propTypeThisDb,nodeDbQuery))

		except Exception:
			exc = sys.exc_info()[0]
			lib_common.ErrorMessageHtml(
				"Unexpected exception:%s" % ( str(sys.exc_info())))  # cgiEnv.OutCgiRdf()

	cgiEnv.OutCgiRdf("LAYOUT_RECT",arrProps)

if __name__ == '__main__':
	Main()

# http://www.easysoft.com/developer/languages/python/pyodbc.html


# Now that we have detected a SQL query from the memory of a process,
# we want to associate it to genuine database objects: tables, views etc...


# This SQL query is analysed with the available databases.
# It might check the exact SQL syntax.
# It would be nice to detect the database library which would give a hint.

# List:
# - Oracle
# - sqlite
# - sqlserver : No need of credentials but how to define the database ? With the file name.

#######################################################################################
# WHY WE NEED TO ADD EXTRA DATA THAN THE QUERY

# If we scan the memory of a process, we have the list of sqlite files which are open.
# But which one is relevant ? Maybe none of them.

# Could we have, when displaying the query, a placeholder representing the database ?
# Or, when parsing the query, it would be associated to a process ?
# The key is for example, the process, in which we can explore the databases it is linked to,
# or its connections to sockets, or the open files.
# The process plus the credentials.

# So: entity.py?type=sql/query,qry="select ",pid=12345
# And each database type can take this pid and returns possible credentials (Or filenames if sqlite):
# That is, a function which take a list of sheet names and returns a list of table or view nodes.
# For example, the sqlite module can take all sqlite files open by a process,
# and find which has these table names, and all of them.
# Or the Oracle module checks if the process is linked with Oracle,
# checks to which database this process is connected to, and from there returns the oracle table nodes.
# If connected to several Oralce databases, try all of them (Extremely rare).

# If the pid is not given, the sheets are simple sheets, not tables.
# This applies for a sql query found in a text file or a program, that is, a file.
# Still, with just a file name, we can grab some information, for example the database library we are linked with.
# Both information can be used together, it cannot harm.
# And if the pid is there, it also informs that the query is found in the program, not in the memory.
#######################################################################################

# Mais ca ne colle pas dans le cas ou on cherche dans une base de donnees
# les queries en cours d'execution. Dans ce cas, ce sera:
# xid=oracle/db.Db=XE
# xid=sqlserver/dsn.Dsn=mySqlServerDataSource
# Ou alors on tente le coup des arguments variables ?
# Ontology = ["Query"] et c est tout.
# Mais le Uri: MakeuriFromDict( ..., {"Pid":pid, } ) etc...
# Si on n a que le pid, on va chercher les librairies et les credentials et proposer
# plusieurs liens du type ?xid=sql/query,query="kjhkj",type=oracle,db=XE
# Donc on reboucle, c est coherent.
# Ca permet de tenter plusieurs contextes de bdd.
# Ca montre aussi qu il y a une vraie difference entre '?query="lkjhlkjh",pid=123' d'une part
# et d'autre part: '?query="lkjhlkjh",type=oracle,db=XE' ou encore '?query="lkjhlkjh",type=odbc,dns=SysMachin'
# ou bien: '?query="lkjhlkjh",type=sqlite,filnam=toto.sqlite'
# Peut etre pourrait-on sous-classer ?
# sql/query/in_memory_query
# sql/query/in_database_query
# sql/query/in_database_query/oracle
# sql/query/in_database_query/sqlserver
# sql/query/in_database_query/sqlite
#
# On pourrait avoir alors une sorte de convention pour les bases de donnees
# capables d executer du SQL, et qui rendraient une liste de nodes si on leur passe
# une liste de noms de tables/vues et un credential. Toutes les tables devraient
# exister avec cette connection. En fait, il suffirait de compiler la requete.
# On aurait les URLs suivants:
# '?query="lkjhlkjh",type=oracle,key=XE'
# '?query="lkjhlkjh",type=odbc,key=SysMachin'
# '?query="lkjhlkjh",type=sqlite,key=toto.sqlite'
# ... etant entendu que "key" etant une clef dans lib_credentials?

# Eventuellement on pourrait avoir des mots-clefs indiquant le type de la base
# de donnees, son nom, les credentials etc...
# Ca permettrait de repartir des tables vers la base.
# Il n y aura pas de classe oracle/query ou sql/server/query ou sqlite/query:
# Car une query n est pas un objet et meme au sein d une base connue, le resultat d une query depend des
# circonstances.
# En revanche, on aura quelque chose comme:
# type=sql/query?Id="select *",context_type=oracle,context_argument=XE,context_credential=???
#
# Et dans oracle/__init__.py, on aura un objet permettant de:
# - mapper les "sql/sheet" vers des tables ou des views pour une credential donnee.
# - Executer la query.
# - Dire si la syntaxe de la query est valide pour ce type de BDD.
# - Lister les credentials pour ce type de BDD.

# Peut-etre que la derivation reviendrait a ajouter des clefs a l ontologie ?
# "sql/query"               ["Query"]
# "sql/query/CIM_Process"   ["Query","Pid"]
# "sql/query/CIM_DataFile"  ["Query","Filename"]
# "sql/query/oracle/db"     ["Query","Db"]
# "sql/query/odbc/dsn"      ["Query","Dsn"]
# "sql/query/sqlite/file"   ["Query","Filename"]
#
# Pour les sheets, c est different: On ne les utilise que si on n a
# aucune information sur la connection ou la db
#
# Dans un premier temps, on ne va pas concatener les ontologies car ce n est pas necessaire.
# Toutefois, on va s inscrire dans ce cadre, desfois que ca resolve certains problemes.
# A la limite, ce serait commode d indiquer dans "sql/query/__init__.py" la liste
# des types associes: "CIM_Process", "CIM_DataFile", "oracle/db", "odbc/dsn", "sqlite/file"
# et dire que les mots-clefs sont la conjonction des deux.
#
# http://127.0.0.1:8000/htbin/entity.py?xid=sql/query.Query=CglzZWxlY3Q1MQoJ,Pid=0,File=
#
# On dit: Si le type n existe pas, on remonte jusqu a ce qu il existe, et on suppose
# que ce qui suit est un type a part entiere, dont on va chercher l ontologie etc...
# On peut meme renouveller le processus.
#
# http://127.0.0.1:8000/htbin/entity.py?xid=sql/query/CIM_Process.Query=CglzZWxlY3Q1MQoJ,Pid=1234
#
# http://127.0.0.1:8000/htbin/entity.py?xid=sql/query/CIM_DataFile.Query=CglzZWxlY3Q1MQoJ,Name="toto.sql"
#
# http://127.0.0.1:8000/htbin/entity.py?xid=sql/query/oracle/db.Query=CglzZWxlY3Q1MQoJ,Db="XE"
#
# Il faut donner a cette manipulation, ne signification vraiment forte et facile a reutiliser,
# sinon c est trop complique.
# Par ailleurs, il faut de toute facon ajouter aux modules de BDD (Et seulement a ceux-ci)
# une fonction specifique recevant une liste de sheets et renvoyant une liste de nodes.
# La aussi, une exception.
#
# Autre probleme: Le type "sql/query/odbc/dsn" ne correspond pas a un dossier reel.
# On peut certes afficher le dossier le plus long possible et consider que ce qui suit
# correspond a un autre type. Mais si par hasard on cree le dossier "sql/query/odbc/",
# alors l idee de sous-type perd son sens, et il faudrait transformer l URL
# en "sql/query/odbc/odbc/dsn" ?
#
# Et ou va-t-on mettre la fonction de transformation: pid+query=>nodes-list ?
# Dans un sous-dossier local a "sql/query" ou bien dans "oracle/db" ?
#
# On doit avoir une liste explicite des types de bdd auxquelles on passe
# comme parametre le pid et la query.
# On peut certes utiliser la concatenation de types pour exprimer
# les differentes derivations de la query, mais ca ne suffit peut-etre pas.
#
# * Si PID, on essaye les differents types de BDD qui:
# - verifient si le process utilise cette BDD (Ou bien ouvre un fichier sqlite).
# - Si la syntaxe est OK.
# - Et renvoient une liste de liens, maxi un par credential de ce type de BDD.
# * Si la query est dans un fichier: Meme chose moins test pid.
#
# Ces liens sont Query+bd ou dsn etc... et donc sont composites,
# representent vraiment une query pour cette BDD particuliere.

# On pourrait aussi bien avoir: "odbc/dsn/query" ou "oracle/db/sql/query".
# En effet, quand on affiche les queries d une base de donnees Oracle, ou sqlserver,
# il faut aussi naturellement creer un lien de query.
#
# Ca ressemble en effet a l association de plusieurs types.
# Mais comment va-t-on fabriquer les URIs sans devoir tous les enumerer ?
#
# Et est-ce que ce n est pas simplement le concept d association ?
# Peut-etre un peu plus restreint: C est une paire d objets.
# Mais aussi l idee de sous-objets.
#
# Il faudrait que l'association de deux objets se fasse avec un MakeUri
# ameliore, et base sur UriMakeFromDict.
#
# D un autre cote on ne veut pas disperser ce qui concerne Oracle par example.
# Une query SQL est une sorte de type generique, qui ne depend pas
# d une librairie particuliere ou d'un module.
# Le truc est que:
# * On a besoin d associer une query a des credentials specifiques: query+connection ou bien query+process
# * Quand on examine query+process, on veut lister les query+connection
#
# Autrement dit, comprendre "CIM_Process/query" comme "Une query dans le contexte d'un process".
# Idem pour "oracle/db/query", "sqlserver/dsn/query" et "sqlite/file/query".
# Avec le mecanisme d'heritage de l'ontologie.
# Pour faire simple, on peut ecrire:
# oracle.db.query.EntityOntology(): return oracle.db.EntityOntology() + ["Query"]
# Idem pour MakeUri qui recevra (*argv).
# Mais comment lier ces directory ?
# De plus, on faire ecrire plusieurs fois cette operation, alors qu on devrait seulement ecrire
# dans oracle/db/query/__init__.py que on est vraiment une sql/query .
# Et que "sql/query" puisse acceder a ses "types derives".
# Un peu brutal: On pourrait se servir du nom "query" ou bien, ,pour lever toute ambiguite: "oracle/db/SUBCLASSES/sql/query".
# Il suffirait de chercher tous les modules "x/y/z/SUBCLASSES/sql/query".
# Et conventionnellement les ontologies sont concatenees.
# Et dans "x/y/z/SUBCLASSES/sql/query/__init__.py" on met la fonction qui teste si tables ou views
# et renvoie des nodes. Toutefois c est plus naturel d avoir "x/y/z/query/__init__.py"
# mais c est dangereux car ca rompt toute isolation.
# Et en plus on a besoin de "sql".
#
# http://127.0.0.1:8000/htbin/entity.py?xid=oracle/db/SUBCLASSES/sql/query.Db=XE,Query=CglzZWxlY3Q1MQoJ
# http://127.0.0.1:8000/htbin/entity.py?xid=sqlserver/dsn/SUBCLASSES/sql/query.Dsn=XE,Query=CglzZWxlY3Q1MQoJ
# http://127.0.0.1:8000/htbin/entity.py?xid=CIM_Processes/SUBCLASSES/sql/query.Pid=1234,Query=CglzZWxlY3Q1MQoJ
#
# Certes, c est joli, mais au fond a quoi ca sert ? Ca sert a les retrouver facilement a partir de CIM_Process/sql/query.
# En quoi les classes sont elles vraiment composees ?
# Dans sqlserver/dsn/SUBCLASSES/sql/query/init.py , il faudrait explicitement pointer vers sql/query.
# Ca, c est facile.
# Et aussi, quand on cree un "oracle/db/sql/query", c est comme creer un "sql/query" auquel on ajoute
# des attributs.
#
# Va-t-on dans les "SUBCLASSES/x/y/__init__.py" mettre des choses specifiques ?
# Et a quoi ca peut s appliquer en dehors de ce cas ?
# Et comment la rapprocher de concepts WBEM ou WMI ?
# Que faire en presence de "x/y/z/SUBCLASSES/sql/query/SUBCLASSES/machin/truc" ?
#
# OU ALORS ON VA AU PLUS SIMPLE:
# L analyse des requetes va dans lib_sql.py
# On cree independamment:
#   oracle/db/query/
#   sqlserver/dsl/query
#   sqlite/query
#   CIM_Process/sql/query
#   CIM_DataFile/sql/query pour un fichier qui contiendrait une requete.
#
# On s arrange pour boucler sur les bases de donnees: On met une liste dans lib_sql.py .
# On cree
# Du coup sql/query et sql/sheet ne servent que si on a aucune info et qu on doit boucler
# sur toutes les bases de donnees (CIM_DataFile).
# Eventuellement, exemple dans: oracle/db/query/__init__.py
# import sql.query as sql_query
# FunctionX = sql_query.FunctionX
# from sql_query import FunctionY
# Peut etre aussi les decorators
# sql_query.ONtology peut etre capable d ajouter les parametres de oracle/db ou sqlserver/dsn

