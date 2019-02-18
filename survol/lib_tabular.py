# NOTE: THIS IS DEPRECATED BECAUSE REPLACED BY THE CONCEPT OF EVENTS.

import sys
import re
import os
import lib_common
import lib_util
import lib_properties

# Also used for serving the csv file
def TabularFilNam( entity_type, entity_id, header ):
	return "/Tabular." + entity_type + "." + entity_id + "." + header.join(".") + ".csv"

def TabularUrl( entity_type, entity_id, header ):
	return "http:127.0.0.1:" + "PORT" + "/" + TabularFilNam( entity_type, entity_id, header )

plain_old = True

# lib_tabular.AddData( log_strm, grph, node_process, "process", pidstr, [ "cpu", "virt" ], [ tpl[ 1 ], tpl[ 2 ] ] )


# Redondance ici, car on passe le node et le type et l'id.
# TODO: Maybe performance problem because the file reopened each time.
def AddData( log_strm, grph, node, entity_type, entity_id, header, values ):

	if plain_old:
		# Pour le moment, on ne fait qu'ajouter les proprietes.
		lenHead = len(header)
		lenVals = len(values)
		if lenHead != lenVals:
			log_strm.write( "AddData Different lens: %d and %d.\n" % ( lenHead , lenVals ) )
			return
		for idx in range( 0 , lenHead ):
			tmp_property = lib_common.NodeUrl(lib_properties.primns_slash + header[idx])
			grph.add( ( node, tmp_property, lib_common.NodeLiteral(values[idx]) ) )
	return

	# Constraint on the entity id which must be stored in a file name.
	tabFilNam = TabularFilNam( entity_type, entity_id, header )
	csvFil = lib_common.TmpFil(tabFilNam)

	delim = '\t'

	csvFilNam = lib_common.TmpDir() + TabularFilNam( entity_type, entity_id, header )
	csvFd = open( csvFilNam, "a" )
	pos = csvFd.tell()
	if pos == 0:
		log_strm.write( "CVS file %s does not exist.\n" % csvFilNam )
		csvFd.write( "time-stamp" + delim + delim.join( header ) )
	# If the file is too old, we might erase it first.
	# Let's hope the header did not change.
	# We might compare it and create another file if needed.
	
	timeStamp = time.time()
	dtStr = datetime.datetime.fromtimestamp(timeStamp).strftime('%Y-%m-%d %H:%M:%S')
	csvFd.write( dtStr + delim + delim.join( values ) )

	csvFd.close()

	url_csv = TabularUrl( entity_type, entity_id, header )

	# Afficher les csv_data dans le bloc du node, surtout ne pas creer un lien.
	grph.add( ( node, pc.property_csv_data, lib_common.NodeUrl(url_csv) ) )

	return


def ServeFile( filepath ):
	if not re.match( "/Tabular\..*\.csv", filepath ):
		return False

	# lib_util.CopyFile( "text/csv", filepath, sys.stdout )
	lib_util.CopyFile( "text/csv", filepath )

	return True
