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

import sys
import lib_bookmark

def pretty(d, indent=0):
	def Truncate(value):
		strVal = str(value)
		if len(strVal) > 30:
			strVal = strVal[:30] + "..."
		return strVal

	for key, value in d.items():
		print('\t' * indent + Truncate(key))
		if isinstance(value, dict):
			pretty(value, indent+1)
		else:
			print('\t' * (indent+1) + Truncate(value))

def Main():

	filNam = r"C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Docs\bookmarks.html"

	urlNam = "https://www.google.com/bookmarks/bookmarks.html?hl=fr"

	sys.stdout.write("""
		<html><head></head><body>
	""")

	dictBookmarks = lib_bookmark.ImportBookmarkFile(filNam)

	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")

	# sys.stdout.write("RESULT=%s<br/>" % str(dictBookmarks))

	pretty(dictBookmarks)


	sys.stdout.write("""
		</body></html>
	""")

if __name__ == '__main__':
	Main()
