# This opens a browser session with the bookmarks in the bookmark file passed as parameter.
# This is intended for testing.
# It is important that that the urls do not point to local addresses so that the results
# are everywhere the same.
#
# open_bookmarks.py -f <bookmark file> [-d <bookmark directory>] [-b <browser>]
#
# This loads a bookmarks file and display its content.
# This helps for testing: Intersting URLs should be stored
# in the brower favorites for later use and testing.

import os
import sys
import lib_util
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
		INFO("theName=%s",theName)

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

			# TODO: Shoudl display if merge_scripts.py, normal url etc...
			strVal = Truncate(valDict)

			sys.stdout.write(margin * (indent+1) + keyDict + " : " + strVal)

			sys.stdout.write("<BR/>\n")

	try:
		for oneObj in aDict["children"]:
			# sys.stdout.write(margin * indent + Truncate(keyDict) + "<BR/>\n")
			PrettyBkMrks(oneObj, indent+1)
	except KeyError:
		pass


def BookmarksHTML(dictBookmarks):
	sys.stdout.write("""
		<html><head><title>Survol bookmarks</title></head><body>
	""")

	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")
	sys.stdout.write("<br/>\n")

	PrettyBkMrks(dictBookmarks)

	sys.stdout.write("""
		</body></html>
	""")


def Main():

	# Bookmark file for Chrome can be used: "AppData\Local\Google\Chrome\User Data\Default."
	# "C:\Users\rchateau\AppData\Roaming\Microsoft\Windows\Recent\bookmarks.html.lnk"
	# "C:\Users\rchateau\AppData\Roaming\Thunderbird\Profiles\xgv4ydxm.default\bookmarks.html"
	# Google bookmark is another possible source of bookmarks.
	# urlNam = "https://www.google.com/bookmarks/bookmarks.html?hl=fr"
	try:
		filNam = sys.argv[1]
	except:
		filNam = ""

	if not filNam:
		currDir = os.path.dirname(__file__)
		filNam = os.path.join( currDir, "..", "Docs", "bookmarks.html")

	INFO("filNam=%s",filNam)
	dictBookmarks = lib_bookmark.ImportBookmarkFile(filNam)
	BookmarksHTML(dictBookmarks)


if __name__ == '__main__':
	Main()
