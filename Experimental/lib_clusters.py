import re
import sys
import math

# This prints a clusterization of a strings list.
# In our context, this is a map of list of strings, which must be clusterised.
# It is possible that instead of a list of strings, this may be a sub-partition.
# It will be recursively printed.
# The key is the string (or the regular expression) which "summarizes" the cluster.
# This key, combined with the partitionning function which created the partition,
# allows theoretically to rebuild the partition.
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

# This associates to each word, a light version, without numbers.
# It is a partitionner, and as such gets a list of words as arguments,
# and returns a map of list of strings.
# TODO: Do not take into account the file extension.
# TODO: Zap specific keywords: i386 etc...
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

# TODO: Gather strings which are in the same lists for several indices.
# This would fit this situation:
#	"boost_math_c99f-vc140-mt-gd-1_60.dll",
#	"boost_math_c99l-vc140-mt-gd-l_60.dll",
#	"boost_math_c99-vc140-mt-gd-1_60.dll",
# These strings are in the categories 'boost' and 'math' but we might as well
# create the concatenated category 'boost_math'.

# This is not a partitionner: It receives a list of strings but returns a map of maps of strings lists.
# It is called when choosing the best partitionner and it is faster to do all indices in one go
# instead of iterating for all possible column indices.
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

# The function "splitter" can be used to define a split on a specific column.
# - It is necessary to clusterize several classes.
# - It would be great to combine a generator and a splitter, so creating all objects
#   would not be necessary.
# - No need to specify the class on the URL: It is automatically found by choosing
#   the best partionning function (aka splitter).
# - The script creates nodes with partitions. It can force a specific partitionner.
#
# It is possible to add CGI parameters to ask partitionning of specific classes:
# any_script.py?partitioned_class=CIM_Foo&partitioned_class=CIM_Bar
#
# The partitionning is made on the caption. Or should we choose one of the properties ?
#
# Accordingly, the URL of the nodes of each of these groups will be something like,
# if a property is used for partitionning:
# entity.py?xid=CIM_Foo.Name="splitter('.',-1)"['key']
# When clicking on this, it displays all the objects belonging to this partition.
#
# How can we enumerate ? Maybe use another script than entity.py which is not able
# to rebuild a partition, and possibly sub-partitions it, if there are too many objects.
# Btw, how to compose partitioners ?
# This script must for example list the files in a directory, which match a given pattern.
# But this is closely linked to the originating script, and only this one.
#
# How can we link this concept to a WQL query ?
# Or rather, an associator combined with a WQL select query ?
#
def splitter(delim,index):
	# Must return empty string if IndexError exception.
	f = lambda aStr : aStr.split(delim)[index]
	return f

# A partitioner is a function which receives a list of strings
# and returns the same strings split into maps of lists.


# Split on case from lower to upper, which delimitates a word.
def case_down(index):
	def function_result(aStr):
		arrStr = []
		lastUp = None
		currWord = ""
		for ch in aStr:
			if lastUp:
				if islower(ch):
					currWord += ch
				else:
					arrStr.append(currWord)
					currWord = ""
					lastUp = None
			else:
				if isupper(ch):
					lastUp = ch
					arrStr.append(currWord)
					currWord = ch
				else:
					currWord += ch
		return arrStr

	return function_result


# Retirer les nombres hexa : split
# Mais la regex doit tenir compte des caracteres avant et apres ... zut.


# This takes a partition, selects keys whihc have are character long,
# and merge them into the list indexed with an empty string.
# The list indexed with an empty string contains all strings which could not be clusterized
# because they are too "different".
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

# Other ideas of partitions:
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

# Par exemple, des clefs correspondant au split. Rien n’empêche de mettre le code Python.
#
# “split(‘.’)[0]”
# “split(‘[0-9]+’)[1]”
#
# On pourrait pondérer l’entropie avec la longueur de la clef. Longueur moyenne car il y en a plusieurs.
#
# On peut creuser avec :
# - Si longueur =1 , on assimile a rien du tout.
# - Comment comparer deux partitions de longueur moyenne X ?
#   L’information est proportionnelle a la longueur de chaque clef.
#   Entre deux partitions qui feraient les memes buckets,
#   a priori la plus interessante est celle qui prend le plus de caracteres.
#   En realite il faudrait tenir compte d’une seconde partition.
#   Mais justement veut raisonner dans tous les cas.
#
# Une passe pour concatener les partitions identiques ?
# Tres rare, vient d’un probleme de delimiteur. On peut s’en apercevoir en comparant les entropies.
#
# Si entropie identique, passe supplementaire « des fois que ».
#
