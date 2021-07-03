"""
Object class as defined in a software library.
"""

# A record is a collection of fields, possibly of different data types, typically in a fixed number and sequence.
# The fields of a record may also be called members, particularly in object-oriented programming;
# fields may also be called elements, though this risks confusion with the elements of a collection.
#
# The name "record" is chosen to avoid ambiguities with "struct" or "class".


import lib_util
import sys
import logging

# TODO: See CIM_DataFile/linux_nm_records.py and sources_types/com which are based on the same concept of class.


def Graphic_colorbg():
	return "#336699"


def EntityOntology():
	"""
	Name: Is the name of the record.
	Path: The file path where it is defined. It can be a Python module, a linked shared library etc...
	:return: This returns a tuple whose first element is the list of attributes.
	TODO: Maybe, just returning the list is enough and a tuple is not needed.
	"""
	return (["Name", "Path"],)


# Autre idee pour definir un record.
# Il peut etre defini dans un fichier mais on veut exprimer l idee que le meme record existe avec
# plusieurs rrpresentations physiques. Un record, c est a la limite un nom, mais surtout
# une suite de nms de champs (eventuellement avec leus types).
# Ou peut-on trouver un record:
# - Une table est un record.
# - Idem fichier CSV.
# - Classes C++ (doxygen ?), Python, COM.
# Idealement, il faudrait retrouver des records similaires dans plusieurs fichiers ou bases de donnees.
#
# En pratique, les records sont un peu modifies: Champs manquants, orthographie differente,
# ordre des champs differents (ainsi que les types bien entendu).
# Il faudrait les comparer comme des chaines, et donc les rassembler et les traiter.
# L'architecture en scripts s'y prete peu pour le moment, sauf a tout charger puis faire une analyse,
# une grande boucle de comparaison.
# Il faudrait trouver un identifiant qui caracterise un record de facon robuste,
# mais ca ne peut pas permettre d'aller d'un champ vers d'autres ressources: Les records n'ont qu'une definition
# semantique et ne se rattachent pas a des entites concretes.
#
# Si on en a plusieurs, on peut tracer un graphe de dependances en reliant les champs de records differents.
#
"""
On pourrait aussi creer dynamiquement des classes et les rattacher au modele de Survol:
La liste des champs formant une ontologie.
"""


def EntityName(entity_ids_arr):
	entity_id = entity_ids_arr[0]
	try:
		# Trailing padding.
		resu = lib_util.html_escape(entity_id)
		return resu
	except TypeError as exc:
		logging.error("CANNOT DECODE: class=(%s):%s", entity_id, str(exc))
		return entity_id
