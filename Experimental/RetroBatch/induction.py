# Faire des tests en generant des requetes SQL.

import numpy

class induction:
	def __init__(self,size_buffer):
		self.m_list_samples = []
		self.m_map_token_to_index = dict()
		#self.m_num_occurences = []

	@staticmethod
	def tokenize(sample):
		return []

	#Non: Ce qui caracterise un cluster, c est la substitution.
	#La "moyenne" de deux queries, ce sotn les tokens identiaues tandis que les
	#differents sont remplaces par des "variables" (Ou bien on garde les variables deja la).

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
		dist = deltaLen
		while idx < minLen:
			elt1 = sam1[idx]
			elt2 = sam2[idx]
			if elt1 != elt2:
				median[idx] = 'any letter'
				if isinstance( elt1, str) or isinstance( elt2, str):
					dist +=1
			else:
				median[idx] = elt1

		dist += 100 * deltaLen
		return dist,median

	# Quand on ajoute un sample, on calcule sa "moyenne" avec tous les autres samples.
	# ON a une map des "moyennes" et des samples qui produisent cette moyenne:
	# Sample A et B, operation "moyenne": *
	# Si M = A * B, alors M = A * M = M * A = B * M = M * B.
	# Le match se fait avec un score qui represente le nombre de substitutions necessaires.
	# Les moyennes a garder sont celles qui ont beaucoup de participants pour le plus faible score.
	# En effet, s'il faut tout substituer, ca ne vaut pas le coup.
	# On pourrait confronter un sample avec une "moyenne" mais ca peut fort bien creer une nouvelle "moyenne"
	# s'il faut substituer de nouvelle svariables/
	# Cette nouvelle "moyenne" va recevoir aussi tous les samples de l'ancienne mais avec un score plus grand
	# car il y a davantage de substitutions.





	def token_to_index(self,token):
		pass

	def add_sample(self,sample):
		lstToks = induction.tokenize(sample)
		lstIndices = [ self.token_to_index(tok) for tok in lstToks ]

		self.m_list_samples.append( induction.tokenize(lstIndices) )

	def clusterize(self):
		num_tokens = len(self.m_map_token_to_index)
		distMatrix = numpy.array( [ zeroes(num_tokens)])

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
