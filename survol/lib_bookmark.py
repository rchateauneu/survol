# Used for:
# - Scanning bookmarks to open them all, for testing.
# - When printing, gets descriptions associated to URLs.

import sys
import re

def GetTagAndRest(aLin):
	aMatch = re.match(r"[^<]*<([^ \t>]*)[^>]*>(.*)\n",aLin)
	if aMatch:
		aTag = aMatch.group(1)
		aRest = aMatch.group(2)
		#sys.stdout.write("Tag=["+aTag+"]<br>\n")
		#sys.stdout.write("Rest=["+aRest+"]<br>\n")
		return ( aTag, aRest )
	else:
		return ( "", "")

def ParseCompleteTag(aTag,aRest):
	# "<H3 ADD_DATE="1508084007" LAST_MODIFIED="1508084007">[Folder Name]</H3>"
	# "<A HREF="http://primhillcomputers.ddns.net/S" ADD_DATE="1497705694" LAST_MODIFIED="1502556991">Linux disk partitions</A>"
	aRegEx = "<" + aTag + "([^>]*)>([^<]*)</" + aTag + ">"

	dtMatch = re.match(aRegEx, aRest)
	if dtMatch:
		parsedTag = {}
		aContent = dtMatch.group(1)
		splitContent = aContent.split(" ")
		for oneSplit in splitContent:
			idxEqu = oneSplit.find("=")
			if idxEqu > 0 :
				oneKey = oneSplit[:idxEqu]
				oneVal = oneSplit[idxEqu+1:]
				parsedTag[oneKey] = oneVal

		parsedTag["label"] = dtMatch.group(2)
		return parsedTag
	else:
		return None


def ImportAux(xmlFil,level):
	sys.stdout.write(( "   " * level ) + "ImportAux\n")
	dictResu = {}

	for aLin in xmlFil:
		# sys.stdout.write("aLin="+aLin+"<br>\n")

		( aTag, aRest ) = GetTagAndRest(aLin)

		if aTag == "DL":
			subDict = ImportAux(xmlFil,level+1)
			dictResu[aTitle] = subDict
		elif aTag == "/DL":
			return dictResu
		elif aTag == "H1":
			# Rest=[Bookmarks Menu</H1>]<br>
			aTitle = aRest[:-4]
			pass
		elif aTag == "DT":
			# Rest=[<A HREF="http://primhillcomputers.ddns.net/S" ADD_DATE="1497705694" LAST_MODIFIED="1502556991">Linux disk partitions</A>]
			parsedTagA = ParseCompleteTag("A",aRest)
			if parsedTagA:
				# "HREF", "ADD_DATE", "LAST_MODIFIED"
				dictResu[parsedTagA["label"]] = parsedTagA["HREF"]
				sys.stdout.write(( "   " * level ) + "dictResu=%s\n"%str(dictResu))
			else:
				# <DT><H3 ADD_DATE="1508084007" LAST_MODIFIED="1508084007">[Folder Name]</H3>
				parsedTagH3 = ParseCompleteTag("H3",aRest)
				if parsedTagH3:
					aTitle = parsedTagH3["label"]
				else:
					sys.stdout.write(( "   " * level ) + "NOMATCH\n")
		elif aTag == "DD":
			# Rest=[Tous les liens pour tester sur Linux]<br>
			aDescription = aRest
		else:
			pass

	return dictResu

def ImportBookmarkFile(filNam):
	xmlFil = open(filNam)

	# inStream = xmlFil.readlines()

	dictBookmarks = ImportAux(xmlFil,0)

	return dictBookmarks

