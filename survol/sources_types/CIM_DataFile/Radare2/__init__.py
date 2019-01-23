"""
Radare2
"""

import lib_util

def Usable(entity_type,entity_ids_arr):
	"""Not an executable or library file"""
	return lib_util.UsableWindowsBinary(entity_type,entity_ids_arr) or lib_util.UsableLinuxBinary(entity_type,entity_ids_arr)

