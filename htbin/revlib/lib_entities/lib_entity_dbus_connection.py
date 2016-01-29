import sys
import pwd
import rdflib
import lib_dbus
import lib_common
import dbus
from lib_properties import pc

# This must add information about the dbus connection.
def AddInfo(grph,node,entity_ids_arr):
	# Example: entity_id=['system', 'org.freedesktop.UDisks2']
	# sys.stderr.write("AddInfo entity_id=%s\n" % str(entity_ids_arr) )

	try:
		busAddr = entity_ids_arr[0]
		# sys.stderr.write("AddInfo busAddr=%s\n" % ( busAddr ) )
		theBus = lib_dbus.MakeBusFromAddress( busAddr )

		connctNam = entity_ids_arr[1]
		# sys.stderr.write("AddInfo connctNam=%s\n" % ( connctNam ) )

		proxy=theBus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
		# sys.stderr.write("AddInfo proxy=%s\n" % str( proxy ) )

		# itf = proxy
		itf = dbus.Interface(proxy, 'org.freedesktop.DBus')

		pid = str(itf.GetConnectionUnixProcessID(connctNam))
		uid = itf.GetConnectionUnixUser(connctNam)
		# sys.stderr.write("AddInfo pid=%s uid=%s\n" % ( pid, uid ) )
	except dbus.exceptions.DBusException:
		# Helas: "org.freedesktop.DBus.Error.AccessDenied"
		exc = sys.exc_info()[1]
		sys.stderr.write("AddInfo Caught=%s\n" % str(exc) )
		# Apparently happens with the first line.
		return
	usrnam = pwd.getpwuid( uid ).pw_name

	nodeProc = lib_common.gUriGen.PidUri(pid)
	nodeUser = lib_common.gUriGen.UserUri(usrnam)
	grph.add( ( node, pc.property_pid, nodeProc ) )
	grph.add( ( node, pc.property_user, nodeUser ) )

