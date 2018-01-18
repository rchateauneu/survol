# This opens a browser session with the bookmarks in the bookmark file passed as parameter.
# This is intended for testing.
# It is important that that the urls do not point to local addresses so that the results
# are everywhere the same.
#
# open_bookmarks.py -f <bookmark file> [-d <bookmark directory>] [-b <browser>]
#

# On charge un fichier bookmark et on en affiche tous les liens.
# On met le contenu dans du json.
# On doit merger a chaque niveau intermediaire.
# Mais aussi demerger et donc FABRIQUER des niveaux intermediaires
# en leur donnant un nom.
# On doit tester le chargement des descriptions qui servent a habiller des rapports.
# C'est pour cette raison qu'il faut pouvoir uploaded un fichier.

# Tester aussi avec un URL.

filName = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Docs\bookmarks.html"

urlNam = "https://www.google.com/bookmarks/bookmarks.html?hl=fr"

import lib_bookmark