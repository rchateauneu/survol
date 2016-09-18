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



#  NOT DONE YET: THIS PARSES SQL QUERIES AND EXTRACTS THE TABLES
# THE PARSING WORKS-ISH BUT THIS IS NOT INTEGRATED IN THE
# FRAMEWORK.
# THIS CAN BE RELATED TO A OS PROCESS ...
# ... OR AN ORACLE SESSION.
# THEREFORE IT HAS TO GO TO A LIBRARY.

import re

# Returns the index of the end of the sub-expression, that is,
# the position of the first closing parentheses which is not opened here.
def closing_parenthesis(stri):
	nb_par = 0
	quoted_simple = False
	quoted_double = False
	escaped = False
	lenStri = len(stri)
	for idx in range( lenStri ):
		ch = stri[idx]

		if ch == '\\':
			escaped = True
			continue

		if escaped:
			escaped = False
			continue

		if ch == "'":
			quoted_simple = not quoted_simple
			continue

		if quoted_simple:
			continue

		if ch == '"':
			quoted_double = not quoted_double
			continue

		if quoted_double:
			continue

		if ch == '(':
			nb_par += 1
		elif ch == ')':
			if nb_par == 0:
				return idx
			else:
				nb_par -= 1
	return lenStri

def not_enclosed(stri,substr):
	#print("subtr=["+substr+"]")
	nb_par = 0
	quoted_simple = False
	quoted_double = False
	escaped = False
	lenStri = len(stri)
	for idx in range( lenStri ):
		ch = stri[idx]

		if ch == '\\':
			escaped = True
			continue

		if escaped:
			escaped = False
			continue

		if ch == "'":
			quoted_simple = not quoted_simple
			continue

		if quoted_simple:
			continue

		if ch == '"':
			quoted_double = not quoted_double
			continue

		if quoted_double:
			continue

		if ch == '(':
			nb_par += 1
		elif ch == ')':
			nb_par -= 1

		#if stri[idx] == "F":
		#	print("nb_par="+str(nb_par)+" str="+stri[idx:idx+20])
		# This is not very efficient.
		if nb_par == 0 and re.match( '^' + substr, stri[idx:], re.IGNORECASE ):
		# if nb_par == 0 and stri[idx:idx + len(substr)].upper() == substr:
			#print("Match substr="+substr+" idx="+str(idx))
			return idx
	return lenStri

schema_rgx = "[A-Za-z_][A-Za-z0-9_$-]*"
table_rgx = "[A-Za-z_][A-Za-z0-9_$-]*"
syno_rgx = "[A-Za-z_][A-Za-z0-9_-]*"
where_rgx = '\s+WHERE'
on_rgx = '\s+ON' # This is for the syntax " JOIN ... ON .."
# schema_table_rgx = schema_rgx + '\.' + table_rgx
table_with_schemas_rgx = "[A-Za-z_][A-Za-z0-9_$\.-]*"

# TODO: Should probably start by splitting based on UNION, INTERSECT etc...
# Anyway the syntax is really complicated.
def parse_sql_subselect(select_tables_txt, lili):
	#print("\nparse_sql_subselect="+select_tables_txt)

	# Maybe it is a simple table followed by a comma etc...

	remtch_subselect = re.match( '^\s*\(\s*SELECT\s+(.*)', select_tables_txt, re.IGNORECASE )
	if not remtch_subselect:
		#print("parse_sql_subselect: Simple select="+select_tables_txt)
		#return parse_sql_select_inside(select_tables_txt,lili)
		remtch_subselect = re.match( '^\s*SELECT\s+(.*)', select_tables_txt, re.IGNORECASE )
		if not remtch_subselect:
			#print("parse_sql_subselect: Simple select="+select_tables_txt)
			return parse_sql_select_inside(select_tables_txt,lili)




	rest_select = remtch_subselect.group(1)
	closing_par = closing_parenthesis( rest_select )
	#print("parse_sql_subselect: closing_par="+str(closing_par)+ " len="+str(len(rest_select) ))

	subq = rest_select[ : closing_par ]
	#print("\nparse_sql_subselect: subq="+subq)
	if not parse_sql_select( subq,lili ):
		return False

	subqs_rest_comma = rest_select[ closing_par + 1 : ]
	#print("\nparse_sql_subselect: subqs_rest_comma="+subqs_rest_comma)

	# Now maybe there is a synonym and a parenthesis.
	#print("Matching join:"+subqs_rest_comma)
	remtch_suite = re.match('^\s*' + syno_rgx + '\s*(,|INNER\s+JOIN|FULL\s+JOIN|JOIN)\s*(.*)', subqs_rest_comma, re.IGNORECASE )
	if not remtch_suite:
		remtch_suite = re.match('^\s*AS\s+' + syno_rgx + '\s*(,|INNER\s+JOIN|FULL\s+JOIN|JOIN)\s*(.*)', subqs_rest_comma, re.IGNORECASE )


	if remtch_suite:
		subqs_rest = remtch_suite.group(2)
		#print("\nparse_sql_subselect (syno and par): subqs_rest="+subqs_rest)
	else:
		# Maybe just the parenthesis
		remtch_suite = re.match('^\s*(,|INNER\s+JOIN|FULL\s+JOIN|JOIN)\s*(.*)', subqs_rest_comma, re.IGNORECASE )
		if remtch_suite:
			subqs_rest = remtch_suite.group(2)
			#print("\nparse_sql_subselect (syno): subqs_rest="+subqs_rest)
		else:
			# Maybe end of subselect ?
			#print("\nparse_sql_subselect (syno): end of subselect: subqs_rest_comma="+subqs_rest_comma)
			remtch_suite = re.match('^\s*' + syno_rgx , subqs_rest_comma, re.IGNORECASE )
			if not remtch_suite:
				remtch_suite = re.match('^\s*AS\s+' + syno_rgx , subqs_rest_comma, re.IGNORECASE )

			if remtch_suite:
				return True
			remtch_suite = re.match('^\s*', subqs_rest_comma, re.IGNORECASE )
			if remtch_suite:
				return True
			return False

	#print("\nparse_sql_subselect: subqs_rest="+subqs_rest)

	remtch_union = re.match( '^\s*UNION\s+(.*)', subqs_rest, re.IGNORECASE )
	if remtch_union:
		if not parse_sql_select( remtch_union.group(1),lili ):
			return False
		return True

	remtch_intersect = re.match( '^\s*INTERSECT\s+(.*)', subqs_rest, re.IGNORECASE )
	if remtch_intersect:
		#print("INTERSECT="+remtch_intersect.group(1))
		if not parse_sql_select( remtch_intersect.group(1),lili ):
			return False
		return True

	remtch_minus = re.match( '^\s*MINUS\s+(.*)', subqs_rest, re.IGNORECASE )
	if remtch_minus:
		if not parse_sql_select( remtch_minus.group(1),lili ):
			return False
		return True

	#print("Recursive subselect="+subqs_rest)
	return parse_sql_subselect(subqs_rest,lili)

# To extract the first table of the tables list in a SELECT statement.
regex_select_tabs_list_where = (
	'^(' + table_with_schemas_rgx + ')\s+AS\s+' + syno_rgx + where_rgx + '(.*)',
	'^(' + table_with_schemas_rgx + ')\s+' + syno_rgx + where_rgx + '(.*)',
	'^(' + table_with_schemas_rgx + ')' + where_rgx + '(.*)',

	# TODO: WRONG: This is for the syntax "FROM ... JOIN ... ON ..."
	# "...INNER JOIN Categories ON Products.CategoryID = Categories.CategoryID WHERE CategoryName = 'Condiments'"
	'^(' + table_with_schemas_rgx + ')\s+AS\s+' + syno_rgx + on_rgx + '(.*)',
	'^(' + table_with_schemas_rgx + ')\s+' + syno_rgx + on_rgx + '(.*)',
	'^(' + table_with_schemas_rgx + ')' + on_rgx + '(.*)',
)

regex_select_tabs_list_nowhere = (
	'^(' + table_with_schemas_rgx + ')\s+AS\s+' + syno_rgx + '(.*)',
	'^(' + table_with_schemas_rgx + ')\s+' + syno_rgx + '(.*)',
	'^(' + table_with_schemas_rgx + ')(.*)',
)

# This is the content of the select, the columns.
def parse_content_select(content_select,lili):
	# print("parse_content_select content_select="+content_select)
	lenTot = len(content_select)

	while content_select != "":
		# The index of the first comma, not between quotes or parentheses.
		idxComma = not_enclosed(content_select, ",")
		if idxComma == lenTot:
			select_column = content_select
			content_select = ""
		else:
			select_column = content_select[:idxComma]
			content_select = content_select[idxComma + 1:]

		# This column might be a subselect.
		#print("parse_content_select select_column="+select_column)
		remtch_subselect = re.match( '^\s*\(\s*SELECT\s+(.*)', select_column, re.IGNORECASE )

		if not remtch_subselect:
			# Another attept with this syntax:
			# "Select OrderCount = (SELECT COUNT(Id) FROM Order) FROM Customer C"
			remtch_subselect = re.match( '^\s*[A-Za-z0-9_$-]+\s*=\s*\(\s*SELECT\s+(.*)', select_column, re.IGNORECASE )

		if remtch_subselect:
			#print("parse_content_select: Simple select="+select_column)

			rest_select = remtch_subselect.group(1)
			closing_par = closing_parenthesis( rest_select )
			#print("parse_content_select: closing_par="+str(closing_par)+ " len="+str(len(rest_select) ))

			subq = rest_select[ : closing_par ]
			#print("parse_content_select: subq="+subq)
			if not parse_sql_select( subq,lili ):
				#print("parse_content_select: FAILED subq="+subq)
				pass

	return

def truncate_group_order(rest_select):
	# print("truncate_group_order rest_select="+rest_select)
	len_rest_select = len(rest_select)

	# We do not take into account an ordering statement.
	idx_order_by = not_enclosed( rest_select, "ORDER\s+BY" )
	#print("parse_sql_select idx_order_by="+str(idx_order_by)+" len_rest_select="+str(len_rest_select))
	if idx_order_by != len_rest_select:
		#print("parse_sql_select bad:"+rest_select)
		rest_select = rest_select[:idx_order_by]

	# TODO: Should search for "group by "
	# We do not take into account an ordering statement.
	idx_group_by = not_enclosed( rest_select, "GROUP " )
	#print("parse_sql_select idx_order_by="+str(idx_group_by)+" len_rest_select="+str(len_rest_select))
	if idx_group_by != len_rest_select:
		#print("parse_sql_select bad:"+rest_select)
		rest_select = rest_select[:idx_group_by]

	return rest_select

def parse_sql_select(rest_select,lili):
	len_rest_select = len(rest_select)
	#print("parse_sql_select:"+rest_select)

	idx_from = not_enclosed( rest_select, "FROM\s" )
	#print("parse_sql_select idx_from="+str(idx_from)+" len="+str(len_rest_select))
	if idx_from == len_rest_select:
		print("parse_sql_select bad:"+rest_select)
		return False

	# This removes only the end.
	rest_select = truncate_group_order(rest_select)

	content_select = rest_select[ : idx_from ]

	parse_content_select(content_select,lili)

	# After "FROM"
	select_tables_txt = rest_select[ idx_from + 5: ]
	select_tables_txt = select_tables_txt.strip()
	#print("parse_sql_select select_tables_txt="+select_tables_txt)

	return parse_sql_select_inside(select_tables_txt,lili)

# This parse a where clause, looking for subselects.
def parse_subselect_from_where(select_tables_txt_where_clause,lili):
	#print("MAYBE SUBSELECT IN WHERE CLAUSE="+select_tables_txt_where_clause)

	while select_tables_txt_where_clause != "":
		remtch_subselect = re.match( '^.*\(\s*SELECT\s+(.*)', select_tables_txt_where_clause, re.IGNORECASE )
		if not remtch_subselect:
			break

		rest_select = remtch_subselect.group(1)
		closing_par = closing_parenthesis( rest_select )
		#print("parse_sql_subselect: closing_par="+str(closing_par)+ " len="+str(len(rest_select) ))

		subq = rest_select[ : closing_par ]
		select_tables_txt_where_clause = rest_select[ closing_par + 1 : ]
		#print("\nWHERE SUBSELECT MATCH: subq="+subq)

		if not parse_sql_select( subq,lili ):
			#print("CANNOT PARSE SUBSELECT IN WHERE CLAUSE:"+subq)
			continue


def parse_sql_select_inside(select_tables_txt,lili):
	#print("parse_sql_select_inside select_tables_txt="+select_tables_txt)
	while select_tables_txt != "":
		#print("parse_sql_select_inside select_tables_txt=[" + select_tables_txt + "]")
		for regex_select_table_where in regex_select_tabs_list_where:
			remtch_select_table_where = re.match( regex_select_table_where, select_tables_txt, re.IGNORECASE )
			if remtch_select_table_where:
				break

		if remtch_select_table_where:
			lili.append( remtch_select_table_where.group(1) )

			select_tables_txt_where_clause = remtch_select_table_where.group(2)

			parse_subselect_from_where(select_tables_txt_where_clause,lili)

			select_tables_txt = ""
			continue

		#print("regex_select_table_nowhere select_tables_txt="+select_tables_txt)
		for regex_select_table_nowhere in regex_select_tabs_list_nowhere:
			remtch_select_table_nowhere = re.match( regex_select_table_nowhere, select_tables_txt, re.IGNORECASE )
			if remtch_select_table_nowhere:
				#print("Regex:"+regex_select_table_nowhere)
				break

		if remtch_select_table_nowhere:
			#print("Matched1:"+remtch_select_table_nowhere.group(1))
			#print("Matched2:"+remtch_select_table_nowhere.group(2))
			lili.append( remtch_select_table_nowhere.group(1) )

			# Here, the rest of will start by ",", "JOIN", "LEFT AFTER JOIN" etc...
			select_tables_txt_with_left_separators = remtch_select_table_nowhere.group(2)
			mtch_left_sep = re.match("\s*(,|JOIN|LEFT\s+JOIN|LEFT\s+OUTER\s+JOIN|FULL\s+OUTER\s+JOIN|FULL\s+JOIN|INNER\s+JOIN)\s*(.*)",select_tables_txt_with_left_separators, re.IGNORECASE )
			if mtch_left_sep:
				# print("MATCHED JOIN OR COMMA")
				select_tables_txt=mtch_left_sep.group(2)
			else:
				#print("NO JOIN NOR COMMA. Simply the end of the string.")
				select_tables_txt = select_tables_txt_with_left_separators.lstrip( " \t" )


		# Maybe a sub-query.
		#print("parse_sql_select_inside Maybe a SubQuery:"+select_tables_txt)
		if not parse_sql_subselect(select_tables_txt,lili):
			# print("UNKNOWN")
			return False
		# We can end because parse_sql_subselect calls itself.
		# In fact parse_sql_subselect() is enough.
		# TODO: Simplify that.
		select_tables_txt = ""

	#print("parse_sql_select_inside leaving")
	return True


# Gets a SQL query and extracts the tables it depends on.
def parse_sql(sql_text,lili):
	sql_text = sql_text.lstrip( " \t" )

	# This is a stored procedure, we do not process them yet,
	# although it is possible.
	remtch_begin = re.match( '^BEGIN .*', sql_text, re.IGNORECASE )
	if remtch_begin:
		return True

	remtch_declare = re.match( '^DECLARE .*', sql_text, re.IGNORECASE )
	if remtch_declare:
		return True

	# Queries are parsed, but this does not cover all cases.
	# This assumes that queries are normalised: Uppercases, spaces etc...
	# TODO: The insert columns
	remtch_insert = re.match( '^INSERT INTO ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_insert:
		# print("INSERT")
		lili.append( remtch_insert.group(1) )
		# TODO: The inserted value might be a sub-query.
		return True

	remtch_delete = re.match( '^DELETE FROM ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_delete:
		lili.append( remtch_delete.group(1) )
		return True

	remtch_create_table = re.match( '^CREATE TABLE ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_create_table:
		lili.append( remtch_create_table.group(1) )
		return True

	remtch_update = re.match( '^UPDATE ([^ ]*)', sql_text, re.IGNORECASE )
	if remtch_update:
		lili.append( remtch_update.group(1) )
		return True

	# FIXME: This will match the last "FROM" even if this is in a sub-query.
	remtch_select = re.match( '^SELECT\s+(.*)', sql_text, re.IGNORECASE )
	if remtch_select:
		if parse_sql_select( remtch_select.group(1), lili ):
			return True

	remtch_with = re.match( '^WITH ' + table_rgx + ' AS \((.*)', sql_text, re.IGNORECASE )
	if remtch_with:
		rest_with = remtch_with.group(1)
		closing_par = closing_parenthesis( rest_with )

		subqA = rest_with[ : closing_par ]

		# It can only be a SELECT, this is a sub-query, and explicitly mentioned in the regex.
		# print("\nSubQ1=" + subqA )

		if not parse_sql( subqA ):
			return False

		# Probably a SELECT, not sure of what WITH accepts as query.
		subqB = rest_with[ closing_par + 1 : ]
		# print("\nSubQ2=" + subqB )
		if not parse_sql( subqB ):
			return False
		return True

	return False


# On peut appeler ca sql_dependencies et en faire un module a part.


def extract_sql_tables(sql):
	sqlClean = sql.replace("\n"," ")
	tmpList = []
	parse_sql(sqlClean,tmpList)
	# There might be duplicates.
	tmpList = sorted(set(tmpList))
	return tmpList






################################################################################


# We need this.
import sqlparse
################################################################################


# On va changer le type ???
theRegExs = {
	"SELECT": "select ",
	"INSERT": "insert "
}


def SqlRegularExpressions():
	return theRegExs


################################################################################

def SqlQueryToObjects(sqlQuery):
	return

################################################################################
################################################################################

################################################################################
