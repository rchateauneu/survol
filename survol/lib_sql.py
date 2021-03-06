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

# For SQL Server:

"""
SELECT * FROM sys.dm_exec_sessions where host_name is not null

SELECT sqltext.TEXT,
req.session_id,
req.status,
req.command,
req.cpu_time,
req.total_elapsed_time
FROM sys.dm_exec_requests req
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext

#select sqltext.TEXT,* from sys.dm_exec_requests req
#CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext

SELECT sqltext.TEXT,
req.session_id,
req.status,
req.command,
sess.host_process_id
FROM sys.dm_exec_requests req, sys.dm_exec_sessions sess
where sess.session_id = req.session_id
CROSS APPLY sys.dm_exec_sql_text(sql_handle) AS sqltext

"""
################################################################################
# Probleme similaire: Des fichiers relatifs. Pour le moment
# on ne peut pas en faire grand'chose. Toutefois dans l avenir
# ne pas s interdire de les exploiter a partir de RDF.

import re
import logging

import sqlparse


################################################################################

syno_rgx = "[A-Za-z_][A-Za-z0-9_-]*"
table_with_schemas_rgx = r"[A-Za-z_][A-Za-z0-9_$\.-]*"

# This match a table name or a an alias definition.
regex_tab_nam = [
    '^(' + table_with_schemas_rgx + r')\s+AS\s+' + syno_rgx + r'\s*$',
    '^(' + table_with_schemas_rgx + r')\s+' + syno_rgx + r'\s*$',
    '^(' + table_with_schemas_rgx + r')\s*$',
 ]


def _parse_append(tok, result, margin):
    """The input token contains a table name or an alias definition."""
    for rgx in regex_tab_nam:
        remtch = re.match(rgx, tok.value, re.IGNORECASE)
        if remtch:
            result.append(remtch.group(1))
            return True
    return False


def _is_noise(tok):
    return tok.ttype in [sqlparse.tokens.Whitespace, sqlparse.tokens.Punctuation, sqlparse.tokens.Whitespace.Newline]


def _process_select_tokens(sql_obj, depth=0):
    result = []
    depth += 1
    if hasattr(sql_obj, "tokens"):
        in_from = False
        was_from = False
        sql_keywords = ["FROM", "FULL JOIN", "INNER JOIN", "LEFT OUTER JOIN", "LEFT JOIN", "JOIN", "FULL OUTER JOIN"]
        for tok in sql_obj.tokens:
            if _is_noise(tok):
                continue

            if in_from:
                was_from = True

            if was_from:
                if tok.ttype is not None:
                    was_from = False

            if was_from:
                if isinstance(tok, sqlparse.sql.Identifier):
                    if _parse_append(tok, result, depth):
                        continue
                elif isinstance(tok, sqlparse.sql.IdentifierList):
                    for subtok in tok.tokens:
                        if _is_noise(subtok):
                            continue
                        if not _parse_append(subtok, result, depth):
                            # Subselect ???
                            result += _process_select_tokens(subtok, depth)
                    continue
                else:
                    logging.warning("TODO: Case not implemented.")
                    pass

            in_from = (tok.ttype == sqlparse.tokens.Keyword) and tok.value.upper() in sql_keywords

            result += _process_select_tokens(tok, depth)

    return result


def _process_update_tokens(sql_obj, depth=0):
    keywrd_found = False
    for idx in range(0, len(sql_obj.tokens)):
        tok = sql_obj.tokens[idx]

        if _is_noise(tok):
            continue

        if keywrd_found:
            result = _process_select_tokens(sql_obj)

            if isinstance(tok,sqlparse.sql.Identifier):
                if _parse_append(tok, result, depth):
                    return result
            elif isinstance(tok, sqlparse.sql.IdentifierList):
                for subtok in tok.tokens:
                    if _is_noise(subtok):
                        continue
                    if not _parse_append(subtok, result, depth):
                        # Subselect ???
                        result += _process_select_tokens(subtok, depth)
                return result

        if tok.ttype == sqlparse.tokens.Keyword.DML:
            if tok.value.upper() != "UPDATE":
                return ["NonSense"]
            keywrd_found = True

    return ["Nothing"]


def _process_delete_tokens(sql_obj, depth=0):
    # TODO: This is not finished.
    return _process_select_tokens(sql_obj, depth + 1)


def _process_insert_tokens(sql_obj, depth=0):
    # TODO: This is not finished.
    return _process_select_tokens(sql_obj, depth + 1)


def _process_create_tokens(sql_obj, depth=0):
    # TODO: This is not finished.
    return _process_select_tokens(sql_obj, depth + 1)


statement_to_func = {
        "SELECT": _process_select_tokens,
        "UPDATE": _process_update_tokens,
        "DELETE": _process_delete_tokens,
        "INSERT": _process_insert_tokens,
        "CREATE": _process_create_tokens,
}


def _get_statement_type(sql_qry):
    """Returns "SELECT" etc.. based on the query type."""
    for tok in sql_qry.tokens:
        if tok.ttype == sqlparse.tokens.Keyword.DML:
            return tok.value.upper()
        pass
    return ""


def TableDependencies(sql_query):
    """This returns the list of tables that a query depends on."""
    logging.debug("sql_query=%s", sql_query)
    statements = list(sqlparse.parse(sql_query))
    all_tabs = []
    for sql_obj in statements:
        if sql_obj.value.strip() == "":
            continue
        query_type = _get_statement_type(sql_obj)
        func = statement_to_func[query_type]
        result = func(sql_obj)
        # Table names might be case-sensitive, it is database dependent.
        # https://stackoverflow.com/questions/153944/is-sql-syntax-case-sensitive
        uniq_res = sorted(set(res for res in result))
        all_tabs.extend(uniq_res)

    return all_tabs

################################################################################


def _is_sub_select(parsed):
    if not parsed.is_group:
        return False

    if not hasattr(parsed, "tokens"):
        return False

    for item in parsed.tokens:
        if item.ttype is sqlparse.tokens.Keyword.DML and item.value.upper() == 'SELECT':
            return True
    return False


def _sql_query_walk_nodes_recurs(parent_node, sql_obj, the_function, depth):
    """It calls a function on each node, and recursively calls itself.
    For debugging purpose, so we can display the nodes with a text margin
    whose length is proportional to the node depth."""

    is_sub = _is_sub_select(sql_obj)
    if is_sub:
        str_qry = sql_obj.value
        par_first = str_qry.find("(")
        if par_first >= 0:
            par_last = str_qry.rfind(")")
            str_qry = str_qry[par_first+1:par_last]
        the_function(parent_node, str_qry, depth)
        actual_parent = sql_obj.value
        depth += 1
    else:
        actual_parent = parent_node

    if hasattr(sql_obj, "tokens"):
        for tok in sql_obj.tokens:
            _sql_query_walk_nodes_recurs(actual_parent, tok, the_function, depth)


def SqlQueryWalkNodes(sql_query, the_function):
    """For debugging purpose only. It allows to visit each node
    of the SQL query and display it."""
    statements = list(sqlparse.parse(sql_query))
    for sql_obj in statements:
        if sql_obj.value.strip() == "":
            continue
        _sql_query_walk_nodes_recurs("", sql_obj, the_function, 0)


################################################################################

# TODO: Eliminate the last double-quote if the query is taken from
# a source file and is enclosed by quotes. Example:
# sqlQuery1 = "select * from AnyTable"
# Here, the terminating quote is added to returned query.

# These regular expressions are used to detect SQL queries in plain text,
# which can be a text file, or the heap memory of a running process.
# They must be used with re.IGNORECASE
# TODO: Maybe have one regular expression only,
# TODO: so we would scan the memory or file content, once only.
_printables = r"[ ,a-z_0-9\.='\"\+\-\*\$\(\)%]*"
_the_reg_exs = {
    r"SELECT": r"select\s+" + _printables + r"\s+from\s+" + _printables,
    r"INSERT": r"insert\s+" + _printables + r"\s+into\s+" + _printables,
    r"UPDATE": r"update\s+" + _printables + r"\s+set\s+" + _printables,
}


def SqlRegularExpressions():
    return _the_reg_exs

################################################################################

# TODO: Si une query est trouvee dans un fichier, et qu on veut savoir dans quelle
# TODO: base de donnees elle est utilisee, il faut iterer
# TODO: sur toutes les bases de donnees de chacun de ces types, en tenant compte aussi
# TODO: de la syntaxe du SQL.
# TODO: Si la requete vient de la memoire d un process, on peut verifier en plus
# TODO: a quelles bases l'executable est linke. Et eventuellement les sockets
# TODO: du process.
# TODO: Aussi, si le schema est donne. Car a priori il faut essayer tous
# TODO: les credentials.
# TODO: Voir aussi si ce type de BDD fonctionne sur la machine en question, bien entendu.
listModulesUsingSqlQueries = [
    ("sources_types.oracle", "__init__.py"),
    ("sources_types.sqlserver", "__init__.py"),
    ("sources_types.sqlite", "__init__.py"),
    ("sources_types.odbc.dsn", "__init__.py"),
    ("sources_types.CIM_Process.memory_regex_search", "search_connection_strings.py")
]

################################################################################
