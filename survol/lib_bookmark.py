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
		return ( aTag, aRest )
	else:
		return ( "", "")

# Any string will do if it is not "HREF", "ADD_DATE", "ICON", "ICON_URI" etc...
labelTag = "name"

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

				# Strip the double-quotes.
				if ( oneVal[0] == '"' ) and (oneVal[-1] == '"'):
					oneVal = oneVal[1:-1]
				parsedTag[oneKey] = oneVal

		parsedTag[labelTag] = dtMatch.group(2)
		return parsedTag
	else:
		return None


def ImportChildren(xmlFil,level):
	#sys.stdout.write(( "   " * level ) + "ImportAux\n")
	arrChildren = []

	for aLin in xmlFil:
		#sys.stdout.write("aLin="+aLin+"<br>\n")

		( aTag, aRest ) = GetTagAndRest(aLin)

		if aTag == "DL": # This comes last.
			subArray = ImportChildren(xmlFil,level+1)
			if not arrChildren:
				arrChildren.append( {"name":"ROOT"})
			subObj = arrChildren[-1]
			subObj["children"] = subArray
		elif aTag == "/DL":
			break
		elif aTag == "H1":
			# Rest=[Bookmarks Menu</H1>]<br>
			aTitle = aRest[:-5]
		elif aTag == "DT":
			# Rest=[<A HREF="http://primhillcomputers.ddns.net/S" ADD_DATE="1497705694" LAST_MODIFIED="1502556991">Linux disk partitions</A>]
			parsedTag = ParseCompleteTag("A",aRest)
			if not parsedTag:
				# <DT><H3 ADD_DATE="1508084007" LAST_MODIFIED="1508084007">[Folder Name]</H3>
				parsedTag = ParseCompleteTag("H3",aRest)
			#sys.stdout.write(( "   " * level ) + str(parsedTag) + "\n")
			arrChildren.append(parsedTag)
		elif aTag == "DD":
			# It comes after "DT"
			# Rest=[Tous les liens pour tester sur Linux]<br>
			aDescription = aRest.strip()
			if aDescription:
				subObj = arrChildren[-1]
				subObj["description"] = aDescription
		else:
			pass

	return arrChildren

def ImportBookmarkFile(filNam):
	xmlFil = open(filNam)

	arrChildren = ImportChildren(xmlFil,0)

	return {
		"name" : "Bookmarks",
		"children" : arrChildren
	}

# TODO: Provide a lookup for URLs, insensitive ot the display mode,
# TODO: returning description or other data given an URL.