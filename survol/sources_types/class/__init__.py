"""
Object class as defined in a software library.
"""

import lib_util
import sys
import logging

# TODO: See CIM_DataFile/linux_nm_classes and sources_types/com which are based on the same concept of class.


def Graphic_colorbg():
	return "#336699"


def EntityOntology():
	return (["Name", "File"],)


def EntityName(entity_ids_arr):
	entity_id = entity_ids_arr[0]
	try:
		# Trailing padding.
		resu = lib_util.html_escape(entity_id)
		return resu
	except TypeError as exc:
		logging.error("CANNOT DECODE: class=(%s):%s", entity_id, str(exc))
		return entity_id
