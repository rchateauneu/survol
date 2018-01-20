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


# De out facon il faut soit stocker l emplacement du fichier,
# soit le charger.
# Il vaut mieux que la configuration indique l emplacement du fichier
# Pour aller a l essentiel, on convient que le fichier de bookmark est avec le fichier de credentials.
# L'upload se fera plus tard si necessaire.

import sys
import lib_bookmark

def PrettyBkMrks(aDict, indent=0):
	margin = "&nbsp;" * 10

	def Truncate(value):
		value = value.strip()
		if not value:
			return "<empty>"
		strVal = str(value)
		if len(strVal) > 40:
			strVal = strVal[:40] + "..."
		return strVal

	try:
		theName = aDict["name"]
	except KeyError:
		theName = "No name"

	try:
		urlHRef = str(aDict["HREF"])

		strLnk = "<a href='%s'>%s</a>" % (urlHRef,Truncate(theName))
		sys.stdout.write(margin * (indent+1) + strLnk)

		if urlHRef.find("merge_scripts.py") >= 0:
			sys.stdout.write(" MERGE \n")
	except KeyError:
		# If no URL
		strVal = Truncate(theName)
		sys.stdout.write(margin * (indent+1) + strVal)

	sys.stdout.write("<BR/>\n")


	for keyDict in sorted(aDict.keys()):
		if keyDict not in ["children","HREF","name"]:
			valDict = aDict[keyDict]

			# Afficher si merge_scripts.py, si lien normal etc...
			strVal = Truncate(valDict)

			sys.stdout.write(margin * (indent+1) + keyDict + " : " + strVal)

			sys.stdout.write("<BR/>\n")

	try:
		for oneObj in aDict["children"]:
			# sys.stdout.write(margin * indent + Truncate(keyDict) + "<BR/>\n")
			PrettyBkMrks(oneObj, indent+1)
	except KeyError:
		pass




def Main():

	# Bookmark file for Chrome should be here: "AppData\Local\Google\Chrome\User Data\Default."
	# "C:\Users\rchateau\AppData\Roaming\Microsoft\Windows\Recent\bookmarks.html.lnk"
	# "C:\Users\rchateau\AppData\Roaming\Thunderbird\Profiles\xgv4ydxm.default\bookmarks.html"

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

	PrettyBkMrks(dictBookmarks)


	sys.stdout.write("""
		</body></html>
	""")

if __name__ == '__main__':
	Main()
