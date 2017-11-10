import re
import sys
import math

def AnonymizeArr(splitFilnam):
	strForbidden = "*"

	#The file name extension is not taken into account.
	splitFilnam[-l] = strForbidden

	# no numbers:
	resu = [ strForbidden if tok.isdigit() else tok for tok in splitFilnam ]
	return resu

# The result of a clusterization is a map of arrays, or maps etc...
# The key is the string (or the regular expression)
# which "summarizes" the cluster.
# Ideally it should allow to rebuild it from scratch.
# Maybe a regex or a combination of these.
def PrintCluster(mapClus,lenOnly,level = 0):
	if not mapClus:
		sys.stdout.write("None\n" )
		return

	txtMargin = "   " * level
	for key in sorted(list(mapClus.keys())):
		sys.stdout.write("%s %-40s" % (txtMargin,key)  )
		val = mapClus[key]
		if type(val) == dict:
			sys.stdout.write("\n")
			PrintCluster(val, lenOnly, level + 1)
		elif type(val) == list:
			if lenOnly:
				sys.stdout.write(" %3d elements\n" % (len(val)))
			else:
				sys.stdout.write("\n")
				for elt in sorted(val):
					sys.stdout.write("%s     %.40s\n" % (txtMargin,elt))
		else:
			sys.stdout.write("\nSHOULD NOT HAPPEN %s\n" % (str(val)))

# TODO: Do not take into account the file extension.
# TODO: Zap specific keywords: i386 etc...
# This associates to each word, a light version, without numbers.
def by_hash(lstWords):
	dictClusters = {}
	for wrd in lstWords:
		# The hash key is calculated by replacing digits by a dummy character.
		wrkKey = re.sub("[-\.0-9]+","_",wrd)
		try:
			dictClusters[wrkKey].append(wrd)
		except KeyError:
			dictClusters[wrkKey] = [wrd]
	return dictClusters

# Returns a map of criterias and the associated value.
# Here, it is only the nth-word after split based on digits.
# It is possible to add other discriminant functions.
# The file extension is one of them, arbitrarily labelled with -l.
# Specific keywords or patterns (Such as hexa numbers) etc...
def word_eligibility(oneWrd):
	#This label theoretically allows to rebuild the same clusterization.
	def IndexToTag(idx):
		return "by_columns(%d)" %idx

	wrdSplit = re.split("[-_\.0-9]+",oneWrd)


	# SHOULD NOT TAKE INTO ACCOUNT SPLIT ELEMENTS OF ONE LETTER.
	# EXCEPT IF THE GENERATED SET OF KEYS IS SIGNIFICANT.
	# On pourrait rejeter les colonnes d'un seul caractere.
	# Exemple "d3r4.xll".

	mapCrits = dict()

	lenWrds = len(wrdSplit)

	if lenWrds == 1:
		mapCrits[IndexToTag(0)] = oneWrd
	else:
		for ix in range( lenWrds -1):
			mapCrits[IndexToTag(ix)] = wrdSplit[ix]
		# File extension with a specific index.
		mapCrits[IndexToTag(-1)] = wrdSplit[-1]
	return mapCrits

# Ou alors, algorithme plus progressif: On tokeize et on essaye de rassembler
# les mots dont tous les tokens sont identiques, sauf un, puis sauf deux etc...
# en choisissant le minimum de tokens pour les plus grands clusters possibles.
# Et/Ou: Choisir un token, puis un autre.
# Plusieurs index, un par colonne: Ceux qui ont le token K a l;index N
#
# A la premiere passe, on choisit la colonne dont l'index est le plus petit
# mais avec au moins une clef.
def by_columns(lstWords):
	print("all_clusts numWrds=%s"%len(lstWords))
	allCols = set()
	allEligs = {}
	for oneWrd in lstWords:
		mapCrits = word_eligibility(oneWrd)
		allCols.update(mapCrits.keys())
		allEligs[oneWrd] = mapCrits

	# One partition of the input list, indexed by column number.
	dictClustersArrays = {}
	for oneCrit in allCols:
		currPartition = dict()
		for oneWrd in allEligs:
			mapCrits = allEligs[oneWrd]
			try:
				oneCritVal = mapCrits[oneCrit]
			except KeyError:
				oneCritVal = ""

			try:
				currPartition[oneCritVal].append(oneWrd)
			except KeyError:
				currPartition[oneCritVal] = [ oneWrd ]
		dictClustersArrays[oneCrit] = currPartition
	return dictClustersArrays

def compress(dictClusters):
	# Otherwise "RuntimeError: dictionary changed size during iteration"
	dictKeys = list(dictClusters.keys())
	for keyWrd in dictKeys:

		if keyWrd != "":
			valList = dictClusters[keyWrd]
			if len(valList) == 1:
				try:
					dictClusters[""].extend(valList)
				except KeyError:
					dictClusters[""] = valList
				del dictClusters[keyWrd]

	return dictClusters

# Grouper des objets ayant un parent commun, par proximite de leur qu on remplace par
# une regex.
#
# La propriete passe de key=value a key~regex ou key~=regex ou key=~regex.
# On utilise alors enumerate.py au lieu de entity.py.
# La partie interessante est de clusteriser des listes de chaines et de mettre les
# bonnes regex: hombres, respecter les delimiteurs.
# Ca permet d afficher bcp d objets.
def cluster_maxsize(dictClusters):
	maxSz = 0
	for keyWrd in dictClusters:
		currSz = len(dictClusters[keyWrd])
		if maxSz < currSz:
			maxSz = currSz
	return maxSz

def cluster_count(dictClusters):
	return sum( len(dictClusters[keyWrd]) for keyWrd in dictClusters )

def cluster_entropy(dictClusters):
	numElts = cluster_count(dictClusters)
	invNum = 1.0 / float(numElts)
	entr = 0.0
	for keyWrd in dictClusters:
		currSz = len(dictClusters[keyWrd])
		currProb = float(currSz) * invNum
		elt = currProb * math.log(currProb)
		entr += elt
	return - entr

# We could split string if the prefix is an english word:
# crypt32.pdb
# cryptbase.pdb
# cryptdll.pdb
# cryptsp.pdb
# cryptui.pdb
#
# Or split at transitions between uppercase and lowercase:
# VsGraphicsHelper.pdb
# Now choose the most selective index.
# The goal might be to detect significant patterns (Entropy
# or simply to reduce the number of elements at each level,
# to facilite display.
# Simple criteria: This chooses the index whose max category is the smallest.
# Non car a la limite le meilleur choix sera que des categories de un element.
def get_best_crit1(dictClustArrs):
	bestKeyMinMax = None
	bestKeyEntr = None

	minMax = 999999999
	bestEntr = 0
	for ixKey in dictClustArrs:
		dictClust = dictClustArrs[ixKey]
		print ("")
		print("METHOD="+ixKey)
		PrintCluster(dictClust,True)
		currMax = cluster_maxsize(dictClust)
		currEntr = cluster_entropy(dictClust)
		if currEntr > bestEntr:
			bestEntr = currEntr
			bestKeyEntr = ixKey

		currCnt = cluster_count(dictClust)
		print("Cnt=%d Max=%d Entr=%f Len=%d"%(currCnt,currMax,currEntr,len(dictClust)))
		if currMax < minMax:
			minMasz = minMax
			bestKeyMinMax = ixKey

	print ("")
	print("bestKeyMinMax=%s bestKeyEntr=%s"%(bestKeyMinMax,bestKeyEntr))
	return bestKeyEntr

# First pass to split based on hexadecimal numbers.

