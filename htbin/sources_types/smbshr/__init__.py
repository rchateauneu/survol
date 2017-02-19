"""
Samba shared drive
"""

def EntityOntology():
	return ( ["Id"], )

# This returns a nice name given the parameter of the object.
def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]
	return entity_id

