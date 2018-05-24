# Faire des tests en generant des requetes SQL.

import sys
import numpy

class induction:
	def __init__(self):
		self.m_list_samples = []
		self.m_map_token_to_index = dict()

	@staticmethod
	def tokenize(sample):
		return []

	#Non: Ce qui caracterise un cluster, c est la substitution.
	#La "moyenne" de deux queries, ce sont les tokens identiaues tandis que les
	#differents sont remplaces par des "variables" (Ou bien on garde les variables deja la).

	# Certains tokens peuvent etre substitues plus facilement que d'autres: Chaines (encadrees
	# par des guillemets), et nombres.
	# On aura peut-etre plus vite fait de remplacer tout de suite.

	# This is a kind of Hamming distance.

	@staticmethod
	def query_distance(sam1,sam2):
		len1 = len(sam1)
		len2 = len(sam2)
		if len1 <= len2:
			minLen = len1
			deltaLen = len2 - len1
		else:
			minLen = len2
			deltaLen = len1 - len2

		median = []
		idx = 0
		numSubsts = deltaLen
		while idx < minLen:
			elt1 = sam1[idx]
			elt2 = sam2[idx]
			if elt1 != elt2:
				median[idx] = 'any letter'
				if isinstance( elt1, str) or isinstance( elt2, str):
					numSubsts +=1
			else:
				median[idx] = elt1

		# Si longueurs differentes
		numSubsts += 100 * deltaLen
		return numSubsts,median

	# Comment et pourquoi clusteriser les buffers (aka echantillons) ?
	# On veut les repartir en classes homogenes pour separar les donnees d'une part, du code d'autre part.

	# Quand on ajoute un echantillon, on calcule sa "moyenne" avec tous les autres echantillons.
	# Cette "moyenne" represente les tokens communs entre deux echantillons: C'est une generalisation.
	# On a une map des "moyennes" et des echantillons qui produisent cette moyenne:
	# Echantillons A et B, operation "moyenne": *
	# Si M = A * B, alors M = A * M = M * A = B * M = M * B.
	# Le match renvoie aussi le nombre de substitutions necessaires.
	# Les moyennes a garder sont celles qui ont beaucoup de participants pour le plus faible nombre de substitutions.
	# En effet, s'il faut tout substituer, ca ne vaut pas le coup.
	# On pourrait confronter un echantillon avec une "moyenne" mais ca peut fort bien creer une nouvelle "moyenne"
	# s'il faut substituer de nouvelles variables/
	# Cette nouvelle "moyenne" va recevoir aussi tous les echantillons de l'ancienne mais avec un nombre de substitutions plus grand
	# car il y a davantage de substitutions.
	# Chaque "moyenne" stocke une liste de ( nombre de substitutions, echantillon )

	# On ne stocke pas si le nombre de substitutions est superieur a un seuil (Ex: 50% de la longueur).
	# Quand nouvel echantillon, on compare en premier avec les moyennes.
	# Si aucune ne donne un resultat "satisfaisant", comparer avec les echantillons de la "moyenne"
	# donnant le meilleur resultat ?
	# Ou bien: Au debut chaque echantillon est sa propre "moyenne" et au fur et a mesure, on fusionne ?

	# Eventuellement, ranger les echantillons dans un arbre dont les feuilles sont les echantillons,
	# et les noeuds intermediaires, les "moyennes".
	# Quand un nouvel echantillon arrive, on parcourt l'arbre en largeur d'abord.
	# On s'arrete au meilleur score et eventuellement, on insere un noeud intermediaire ???

	# Des qu'il y a plus de deux echantillons dans la meme moyenne, on supprime les echantillons,
	# on arrete de les stocker ???



	def token_to_index(self,token):
		pass

	def add_sample(self,sample):
		lstToks = induction.tokenize(sample)
		lstIndices = [ self.token_to_index(tok) for tok in lstToks ]

		self.m_list_samples.append( induction.tokenize(lstIndices) )

	def clusterize(self):
		num_tokens = len(self.m_map_token_to_index)
		sys.stdout.write("num_tokens=%d\n"%num_tokens)
		distMatrix = numpy.zeros( (num_tokens,num_tokens,),dtype=int)

		idx1 = 0
		while idx1 < num_tokens:
			sam1 = self.m_list_samples[idx1]
			distMatrix[idx1][idx1] = 0.0
			idx2 = idx1 + 1
			while idx2 < num_tokens:
				sam2 = self.m_list_samples[idx2]
				dst = induction.query_distance( sam1, sam2 )
				distMatrix[idx1][idx2] = dst
				distMatrix[idx2][idx1] = dst
				idx2 += 1
			idx1 += 1

		# http://scikit-learn.org/stable/modules/generated/sklearn.cluster.DBSCAN.html


	def get_clusters(self):
		pass

# Si periodiques:
# Matrice de Markov.
# Detecter les etats qui ont la meme periode
# Reperer la premiere sequence complete.
# On doit avoir les memes regles de tokenisation.

def TestInduction():
	tstData = [
		"insert into table1 values('id1',11,'aa')",
		"insert into table1 values('id2',22,'bb')",
		"insert into table1 values('id3',33,'cc')",
		"insert into table1 values('id4',44,'dd')",
		"update table2 set age=11 where name='id1'",
		"update table2 set age=22 where name='id2'",
		"update table2 set age=33 where name='id3'",
		"update table2 set age=44 where name='id4'",
	]

	induc = induction()
	for tstStr in tstData:
		induc.add_sample(tstStr)

	induc.clusterize()

# It should be modular enough so that he creation of CIM entites could be in a separate HTTP server,
# and this could work on tcpdump socket content.

# At the moment, we are planning to detect the file type,
# and then to extract the case ids, and leave the "skeleton" of queries.
# In fact these "skeletons" are much more characteristic of the type of the stream.


if __name__ == '__main__':
    TestInduction()