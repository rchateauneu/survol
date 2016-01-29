import lib_common
from lib_properties import pc

def AddInfo(grph,node,entity_ids_arr):
	# TODO: Ca serait quand meme mieux de passer au AddInfo un dict plutot qu un tableau.
	dbNam = entity_ids_arr[0]
	# schemaNam = entity_ids_arr[1]
	nodeDb = lib_common.gUriGen.OracleDbUri(dbNam)

	grph.add( ( nodeDb, pc.property_oracle_schema, node ) )

