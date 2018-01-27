"""
Component Object Model registered type
"""

def Graphic_colorbg():
	return "#AAFFC3"


def EntityOntology():
	return ( ["Id"], )

# This returns a nice name given the parameter of the object.
def EntityName(entity_ids_arr):
	entity_id = entity_ids_arr[0]
	return entity_id

