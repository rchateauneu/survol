import lib_common
from lib_properties import pc

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dbNam = entity_ids_arr[0]
	schemaNam = entity_ids_arr[1]
	nodeSchema = lib_common.gUriGen.OracleSchemaUri(dbNam,schemaNam)

	grph.add( ( nodeSchema, pc.property_oracle_table, node ) )

