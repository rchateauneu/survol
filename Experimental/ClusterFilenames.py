import os
import re

import lib_clusters

# The intention is to experiment with clusterizing algorithms.

mypath = "C:/tmp"
mypath = "C:/Users/rchateau/tmp"
mypath = "C:/Users/rchateau/AppData/Local/Temp"

print("Hello")

# Two typical types of strings to sort:
# File names:
# WMI/WBEM moniker (key/value pairs):
#  Handle=1 CSName=fedora22 OSName=Fedora CSCreationClassName=CIM_UnitaryComputerSystem OSCreationClassName=CIM_OperatingSystem CreationClassName=PG_UnixProcess (WBEM) at http://192.168.0.17:5988
#  Handle=10 CSName=fedora22 OSName=Fedora CSCreationClassName=CIM_UnitaryComputerSystem OSCreationClassName=CIM_OperatingSystem CreationClassName=PG_UnixProcess (WBEM) at http://192.168.0.17:5988
#  Handle=100 CSName=fedora22 OSName=Fedora CSCreationClassName=CIM_UnitaryComputerSystem OSCreationClassName=CIM_OperatingSystem CreationClassName=PG_UnixProcess (WBEM) at http://192.168.0.17:5988

# As an example, it takes a list of files.
onlyfiles = []
for (dirpath, dirnames, filenames) in os.walk(mypath):
	onlyfiles.extend(filenames)
	break

print(onlyfiles)

# def AnonymizeArr(splitFilnam):
# 	strForbidden = "*"
#
# 	# The file name extension is not taken into account.
# 	splitFilnam[-1] = strForbidden
#
# 	# ... no numbers:
# 	resu = [ strForbidden if tok.isdigit() else tok for tok in splitFilnam ]
# 	return resu



# Simple criteria: This chooses the index whose biggest category is the smallest.
def best_index_mini_maxi(dictClustersArrays):
	def cluster_maxsize(dictClusters):
		maxSz = 0
		for keyWrd in dictClusters:
			currSz = len(dictClusters[keyWrd])
			if maxSz < currSz:
				maxSz = currSz
		return maxSz

	bestKey = None
	minMaxSz = 999999999
	for ixKey in dictClustersArrays:
		dictClusters = dictClustersArrays[ixKey]
		print("")
		print(ixKey)
		# print(dictClusters)
		currMax = cluster_maxsize(dictClusters)
		print("currMax=%d len=%d"%(currMax,len(dictClusters)))
		if currMax < minMaxSz:
			minMaxSz = currMax
			bestKey = ixKey
	return (bestKey,minMaxSz)

# This takes into account the length of the keys: The longer, the better.

# THIS IS NOT FINISHED.

def best_index_mini_maxi_ponder(dictClustersArrays):
	def cluster_maxsize(dictClusters):
		maxSz = 0
		for keyWrd in dictClusters:
			currSz = len(dictClusters[keyWrd])
			if maxSz < currSz:
				maxSz = currSz
		return maxSz

	bestKey = None
	minMaxSz = 999999999

	# For each column
	for ixKey in dictClustersArrays:
		dictClusters = dictClustersArrays[ixKey]
		print("")
		print(ixKey)
		# print(dictClusters)
		currMax = cluster_maxsize(dictClusters)
		print("currMax=%d len=%d"%(currMax,len(dictClusters)))
		if currMax < minMaxSz:
			minMaxSz = currMax
			bestKey = ixKey
	return (bestKey,minMaxSz)

def clusterize_kol(lstWords):
	dictClustersArrays = lib_clusters.all_clusts(lstWords)

	# Now choose the most selective index.
	# The goal might be to detect significant patterns (Entropy ?),
	# or simply to reduce the number of elements at each level, to facilite display.
	# We could also concatenate adjacent columns.

	(bestKeyMiniMaxi,minMaxSz) = best_index_mini_maxi(dictClustersArrays)
	print("best_index_mini_maxi bestKey=%s minMaxSz=%d"%(bestKeyMiniMaxi,minMaxSz))

	(bestKeyMiniMaxiPonder,minMaxSzPonder) = best_index_mini_maxi_ponder(dictClustersArrays)
	print("best_index_mini_maxi_ponder bestKeyMiniMaxiPonder=%s minMaxSzPonder=%d"%(bestKeyMiniMaxiPonder,minMaxSzPonder))


	return dictClustersArrays[bestKeyMiniMaxi]



print("")
# clusterize(onlyfiles)
print("")
print("")
print("")
bstIdx = clusterize_kol(onlyfiles)
print("")
print("BEST")
print(bstIdx)
