"""
Windows user account
"""

import sys
import rdflib
import psutil
import lib_common
from lib_properties import pc

def EntityOntology():
	return ( ["Name"],)

# This must add information about the user.
def AddInfo(grph,node,entity_ids_arr):
	# Nothing to do.
	return
