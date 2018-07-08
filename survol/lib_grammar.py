# Consider using the Pythonpackage inflect.

# Win32_ReliabilityRecordses
# Win32_LogicalFileAccesses
def ToPlural(eltNam,numNodLst):
	if numNodLst == 1:
		return eltNam

	if not eltNam[-1].isalpha():
		return eltNam

	if eltNam[-1] == "s":
		if (len(eltNam) > 1) and (eltNam[-2] != "s"):
			# Maybe it is already plural.
			return eltNam
		else:
			return eltNam + "es"

	if eltNam[-1] == "y":
		return eltNam[:-1] + "ies"

	return eltNam + "s"

# https://www.theenglishspace.com/grammar/determiners/articles-introduction.html
def IndefiniteArticle(theWord):
	if theWord[0].upper() in "AEIOUY":
		return "an"
	else:
		return "a"
