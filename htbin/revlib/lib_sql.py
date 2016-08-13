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
# ... et pointe vers un record de meme nom et qui a les memes champs

# Que faire si une sheet a des champs qu une table physique n a pas ?

################################################################################

# sources_types/CIM_Process/memory_regex_search/process_search_sql_queries.py

# Extraire une requete SQL d un process peut peut-etre fournir le type de BDD,
# la BDD elle-meme et le schema.
#
# Si on a ces infos supplementaires, les sheets qu on cree vont
# pointer vers les tables, ou vues, ou synonymes physiques.

# Ca affiche toutes les queries en tant que chaines, mais aussi
# les sheets qu on en a extraites.

# On deduit quelques colonnes des sheets: On les affiche comme des liens.
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

# Quand on clique sur une query, ca l affiche totue seule
# mais pas tres interessant car on perd le contexte:
# - Autre queries (Qui permettent de fusionner les sheets).
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


################################################################################


# We need this.
import sqlparse
################################################################################
################################################################################
################################################################################
################################################################################

################################################################################
