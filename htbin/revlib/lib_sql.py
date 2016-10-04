# Not used yet.
# Used to parse process'memory to detect SQL queries,
# then parse them to display the tables and views etc...

# How to detect which kind of database is it ?
# Can use the specific SQL syntax (But this is not reliable), and the libraries.



################################################################################

# Une query et les tables/views qui y apparaissent n appartiennent pas en propre
# a une base de donnees ou un schema, ni meme a un type de base de donnees car on peut utiliser
# le meme texte de requete dans plusieurs BDD.
# De meme dans une requete peuvent jouer le meme role une table ou une vue.

# Donc on pourrait avoir dans "sql/":
#  - une query
#  - une "table" suivie de noms de "champs": Appelons ca une sheet (Comme spreadsheet)

# Par ailleurs, une veritable table ou view, implementerait une sheet,
# cad un nom suivi d'une liste de champs.

# On peut aussi avancer que les sheets de la meme query font forcement partie
# de la meme base de donnees et du meme schema, sous reserve de synonymes
# ce qui nous entraine trop loin.

# Une vraie table, enumere ses champs (On en est certain).
# ... et pointe vers une sheet de meme nom et qui a les memes champs
# Donc pas besoin que la table enumere ses champs ?

# Probleme: Une table Oracle peut fort bien enumerer ses champs,
# en allant chercher dans la BDD.

# Mais une sheet ne peut pas le faire, il faudrait qu'elle trimballe
# ses champs. Mais du coup on ne pourrait plus matcher car la liste des champs
# est forcement incomplete. Ou alors on ajoute un niveau intermediaire
# qui est: "sheet_names+champs" qui pointe vers "sheet_name" et vers les champs d autre part.

# Que faire si une sheet a des champs qu une table physique n a pas ?
# Dans ce cas le match ne devrait pas etre possible, mais il faudrait du code specifique.

################################################################################

# sources_types/CIM_Process/memory_regex_search/scan_sql_queries.py

# Extraire une requete SQL d un process peut peut-etre fournir le type de BDD, la BDD elle-meme et le schema.

# Mais une requete peut aussi venir d un script ou de la memoire d un process, sans autre information.

# On part d un script SQL qui donne une query qui donnent des sheets.
# On part dune base de donnees qui donne des tables, qui donnent des sheets.
# Ce qui est dommage est que pour fusionner, il faut afficher toutes les tables ET leur sheets, ce qui est un peu artificiel.
# On part d une BDD qui donne des queries + base + schema.
# Il faudrait pouvoir associer explicitement une query et une BDD.
# La meme requete peut fort bien etre connectee a plusieurs BDDs.

#
# Si on a ces infos supplementaires, les sheets qu on cree vont
# pointer vers les tables, ou vues, ou synonymes physiques.

# Ca affiche toutes les queries en tant que chaines, mais aussi
# les sheets qu on en a extraites.

# On deduit quelques colonnes des sheets: On les affiche comme des liens.
# Une colonne (ou champ) d une sheet, c est: "sheet_name" + "column_name".
# La sheet complete qui permet d avoir la liste des champs, c est:
# "sheet_name+col1+col2+col3" etc... et qui pointe vers la sheet_name,
# ce qui permet la fusion avec une vraie table Oracle.
# Pour en voir davantage, il faut fusionner le resultat de plusieurs SQL queries.
# D ou l interet d'afficher toutes les queries en meme temps.

# Deux sheets de meme nom venant de deux requetes differentes, sont-elles associees ?
# Oui, c est la meme, car dans un contexte specifique, ca peut etre le meme objet physique.

################################################################################
# sources_types/CIM_DataFile/prog_search_sql_queries.py

# ProC, embedded SQL in C (This exists for Sybase too).
# Any source file: Bash, Python, C, Java etc...

# Search strings in object files, executables, shared libraries.

# We cannot know the database and only sometimes the schema.
# So the displayed sheets do not come with extra urls.

################################################################################

# AFFICHAGE D UNE QUERY ISOLEE

# sources_types/sql/query/__init__.py

# Quand on clique sur une query, ca l affiche toute seule
# mais pas tres interessant car on perd le contexte:
# - Autres queries (Qui permettent de fusionner les sheets).
# - Programme executable ou scripts (P)as tres utile, mais bon).
# - Le process dont on pourrait peut-etre extraire la connection,
#   soit en scannant soit en interrogeant le serveur.

################################################################################

# AFFICHAGE D UNE SHEET ISOLEE

# sources_types/sql/sheet/__init__.py

# Comment aller d'une sheet vers une BDD physique ?
# On propose la liste des bases de donnees et dans chacune d'elles
# on cherche les tables et views et synonymes de meme nom ?
# Et le schema eventuellement intervient ? Si on ne le connait pas on cherche dans tous les schemas.
# Et on verifie que les colonnes dont nous disposons d apres la query,
# existent dans la table ou la view.

################################################################################
# Quand on affiche toutes les queries d un fichier (memoire process etc...)
# il faut les relier par le nom de la sheet ?
# Par les champs eventuellement ?

# Et quand on affiche toutes les queries en cours d execution,
# va-t-on les relier ? On peut mais c est moins interessant.
# On a besoin des schemas bien entendu.
# La aussi, probleme avec les queries car les schemas peuvent etre implicites.
# Donc une table dont le schema est connu, pointe vers une sheet sans schema.

# Chaque query est affichee comme un gros bloc qui pointe vers des champs (Sans schema ni db),
# ces champs pointent eux-meme vers des sheets (Sans schema ni db).

# Quand on parse une query, comme on ne l execute pas, il y aura ambiguite
# sur les champs:
# select CHAMP1, CHAMP2 from TABLE1, TABLE2 WHERE CHAMP3=CHAMP4
# Tout ce qu on peut faire dans le cas general est de lier la query
# aux sheets TABLE et TABLE2. Les noms des champs sont moins importants.

################################################################################

# DEFINITION D UNE SHEET

# On definit une sheet uniquement avec le nom + schema car
# les synonymes et vues peuvent la faire pointer n'importe ou, de toute facon.
# Et donc ce n est pas irrationnel de la faire pointer vers tous les objets
# accessibles, de type table, view ou synonym, dans le bon schema ou bien dans tous.
#
# Si le schema n est pas donne, qu est ce qu on met ??
# Soit on ne le met pas, mais on perd une precision utile,
# ou bien on suppose que s'il est donne, alors aucune autre
# requete ne l'omettra ... C est un peu ose.

################################################################################
# Quand on affiche une query, on affiche aussi les sheet (Uniquement nom + schema).
# Si la facon dont on a trouve la query nous donne des infos supplementaires
# (Connection BDD du process, DLL de l'executable), alors on a un contexte
# qui permettent d ajouter des infos a la sheet: Par exemple, si on a la connection,
# on ira chercher precisement les tables. Si on a le type de bdd,
# on peut ajouter un parametre a lien de recherche, pour cette sheet,
# qui restreint la recherche.
# On peut aussi chercher dans les bases de donnees si le process s y trouve,
# et donc connaitre le schema.
# Mais ces infos ne font pas partie de la definition d une sheet.

# Le truc est que c est un peu dommage, pour chaque table, de doubler
# avec une sheet.

# De plus, il faudrait trouver un moyen pour relier une query avec une vraie BDD,
# sans bien entendu l executer, mais quand meme la compiler.


################################################################################

# oracle/db/executing_queries.py

# Dans Oracle, si on affiche les queries en cours d'execution,
# ca cree des objets de type vers sql/query/__init__.py

# On dispose du contexte necessaire qui fait que les sheets pointent vers
# la bonne table ou view, sans ambiguite. Afficher la sheet
# ne servirait que si on fusionne.

# Probleme: Pour disposer du contexte, on doit partir de la BDD: On ne peut
# pas afficher la query toute seule.

# Ou alors, on cree le type:
# oracle/query/__init__.py
# ... ce qui permet de garder la BDD en parametre ... et quand on affiche
# un objet de type oracle/query ca affiche des sql/sheet ?

################################################################################
# Si on fusionne plusieurs RDF, la meme sheet peut pointer vers des tables
# ou views ou synonymes radicalement differents: C est tout a fait possible
# dans la realite.


################################################################################
# SI sheet ETAIT UNE CLASSE DE BASE DE oracle/table OU oracle/view,
# EST-CE QUE CA APPORTERAIT QUELQUE CHOSE ?

################################################################################

# Maybe this ?
# sources_types/CIM_Process/memory_regex_search/oracle/__init__.py
# sources_types/CIM_Process/memory_regex_search/oracle/extract_connections.py
# sources_types/CIM_Process/memory_regex_search/oracle/search_queries.py

# Probleme: We would have to try all of the directories.
# Practically, a process will be linked to one DB, maybe, exceptionnaly two DBs.

################################################################################
# Probleme similaire: Des fichiers relatifs. Pour le moment
# on ne peut pas en faire grand'chose. Toutefois dans l avenir
# ne pas s interdire de les exploiter a partir de RDF.

import re
import sqlparse


################################################################################

syno_rgx = "[A-Za-z_][A-Za-z0-9_-]*"
table_with_schemas_rgx = "[A-Za-z_][A-Za-z0-9_$\.-]*"

# This match a table name or a an alias definition.
regex_tab_nam = [
	'^(' + table_with_schemas_rgx + ')\s+AS\s+' + syno_rgx + '\s*$',
	'^(' + table_with_schemas_rgx + ')\s+' + syno_rgx + '\s*$',
	'^(' + table_with_schemas_rgx + ')\s*$',
 ]

# The input token contains a table name or an alias definition.
def ParseAppend(tok,result,margin):
	for rgx in regex_tab_nam:
		remtch = re.match( rgx, tok.value, re.IGNORECASE )
		if remtch:
			#print(margin+"Match "+rgx)
			result.append( remtch.group(1) )
			return True
	return False

def IsNoise(tok):
	return tok.ttype in [sqlparse.tokens.Whitespace,sqlparse.tokens.Punctuation,sqlparse.tokens.Whitespace.Newline]

# The margin is only for debugging and display purpose.
def ProcessSelectTokens(sqlObj,depth = 0):
	result = []
	depth += 1
	if hasattr(sqlObj,"tokens"):
		#print(margin.replace("=","*")+str(sqlObj.value)+" => " +str(sqlObj.ttype))

		inFrom = False
		wasFrom = False
		for tok in sqlObj.tokens:
			if IsNoise(tok):
				continue

			if inFrom:
				wasFrom = True

			#print(margin+"val="+tok.value.strip()+" "+str(tok.ttype)+" inFrom="+str(inFrom)+" type="+str(type(tok)))
			#continue

			if wasFrom:
				#print(tok.ttype)
				if tok.ttype is not None:
					wasFrom = False

			if wasFrom:
				#print(margin+"FROM:"+tok.value.strip()+" => "+str(tok.ttype)+" type="+str(type(tok)))
				if isinstance(tok,sqlparse.sql.Identifier):
					if ParseAppend(tok,result,depth):
						continue
				elif isinstance(tok,sqlparse.sql.IdentifierList):
					for subtok in tok.tokens:
						if IsNoise(subtok):
							continue
						#print(margin+"subtok="+subtok.value)
						if not ParseAppend(subtok,result,depth):
							# Subselect ???
							result += ProcessSelectTokens(subtok,depth)
					continue
				else:
					#print("WHAT CAN I DO")
					pass

			inFrom = ( tok.ttype == sqlparse.tokens.Keyword ) \
					 and tok.value.upper() in ["FROM","FULL JOIN","INNER JOIN","LEFT OUTER JOIN","LEFT JOIN","JOIN","FULL OUTER JOIN"]

			result += ProcessSelectTokens(tok,depth)

	return result

def ProcessUpdateTokens(sqlObj,depth=0):
	idx = 0
	keywrdFound = False
	for idx in range(0,len(sqlObj.tokens)):
		tok = sqlObj.tokens[idx]

		if IsNoise(tok):
			continue

		if keywrdFound:
			result = ProcessSelectTokens( sqlObj)

			#print("updtok="+tok.value)
			if isinstance(tok,sqlparse.sql.Identifier):
				if ParseAppend(tok, result, depth):
					return result
			elif isinstance(tok, sqlparse.sql.IdentifierList):
				for subtok in tok.tokens:
					if IsNoise(subtok):
						continue
					# print(margin+"subtok="+subtok.value)
					if not ParseAppend(subtok, result, depth):
						# Subselect ???
						result += ProcessSelectTokens(subtok, depth)
				return result

		if tok.ttype == sqlparse.tokens.Keyword.DML:
			if tok.value.upper() != "UPDATE":
				return ["NonSense"]
			keywrdFound = True

	return ["Nothing"]

def ProcessDeleteTokens(sqlObj,depth=0):
	return ProcessSelectTokens(sqlObj,depth + 1)

def ProcessInsertTokens(sqlObj,depth=0):
	return ProcessSelectTokens(sqlObj,depth + 1)

def ProcessCreateTokens(sqlObj,depth=0):
	return ProcessSelectTokens(sqlObj,depth + 1)

statementToFunc = {
		"SELECT":ProcessSelectTokens,
		"UPDATE":ProcessUpdateTokens,
		"DELETE":ProcessDeleteTokens,
		"INSERT":ProcessInsertTokens,
		"CREATE":ProcessCreateTokens,
}

# Returns "SELECT" etc.. based on the query type.
def GetStatementType(sqlQry):
	for tok in sqlQry.tokens:
		if tok.ttype == sqlparse.tokens.Keyword.DML:
			return tok.value.upper()
		pass
	return ""

# This returns the list of tables that a query depends on.
def TableDependencies(sqlQuery):
	statements = list(sqlparse.parse(sqlQuery))
	allTabs = []
	for sqlObj in statements:
		if sqlObj.value.strip() == "":
			continue
		# print(sqlQry.value)
		queryType = GetStatementType(sqlObj)
		#print("XX="+queryType)
		func = statementToFunc[queryType]
		result = func(sqlObj)
		uniqRes = sorted(set( res.upper() for res in result))
		allTabs.extend(uniqRes)

	return allTabs

################################################################################

def IsSubSelect(parsed):
	if not parsed.is_group:
		return False

	if not hasattr(parsed,"tokens"):
		return False

	for item in parsed.tokens:
		if item.ttype is sqlparse.tokens.Keyword.DML and item.value.upper() == 'SELECT':
			return True
	return False

#Afficher la requete SQL sous la forme d un arbre dont les brqanches sont
#les sous-requetes. Pour ca, on va d abord utiliser sqlparse et afficher recursivement
#l arbre genere.
def SqlQueryWalkNodesRecurs(parentNode, sqlObj,Func,depth):

	isSub = IsSubSelect(sqlObj)
	#print("Q="+sqlObj.value+" isSub="+str(isSub))
	if isSub:
		strQry = sqlObj.value
		parFirst = strQry.find("(")
		if parFirst >= 0:
			parLast = strQry.rfind(")")
			strQry = strQry[parFirst+1:parLast]
		# Func( parentNode, strQry + " " + str(sqlObj.ttype), depth )
		Func( parentNode, strQry, depth )
		actualParent = sqlObj.value
		depth += 1
	else:
		actualParent = parentNode

	if hasattr(sqlObj,"tokens"):
		for tok in sqlObj.tokens:
			#if IsNoise(tok):
			#	continue

			SqlQueryWalkNodesRecurs( actualParent, tok, Func, depth )

def SqlQueryWalkNodes(sqlQuery,Func):
	statements = list(sqlparse.parse(sqlQuery))
	for sqlObj in statements:
		if sqlObj.value.strip() == "":
			continue
		SqlQueryWalkNodesRecurs( "", sqlObj, Func, 0)


################################################################################

# These regular expresssions are used to detect SQL queries in plain text.
# TODO: This is not really appropriate because several regex might be used
# for the same type of querie. Also, it might be simpler and faster
# to use dedicated functions for this plain text exploration.
# For example by searching for "SELECT" then "FROM" etc...
theRegExs = {
	"SELECT": "select ",
	"INSERT": "insert "
}
#
def SqlRegularExpressions():
	return theRegExs

################################################################################
#
# def SqlQueryToObjects(sqlQuery):
# 	return

################################################################################
################################################################################

################################################################################
