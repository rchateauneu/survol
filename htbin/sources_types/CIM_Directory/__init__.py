import os
from sources_types import CIM_DataFile

AddInfo = CIM_DataFile.AddInfo

def EntityOntology():
	return ( ["Name"], )

def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	# A file name can be very long, so it is truncated.
	file_basename = os.path.basename(entity_id)
	if file_basename == "":
		return entity_id
	else:
		# By convention, directory names ends with a "/".
		return file_basename + "/"

