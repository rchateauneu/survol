#!/usr/bin/env python

# http://www.mattfischer.com/blog/?p=494

import dbus
import sys
import pwd

system_bus=dbus.SystemBus()
proxy=system_bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')

# dbus.exceptions.DBusException: org.freedesktop.DBus.Error.AccessDenied: Rejected send message, 7 matched rules; type="method_call", sender=":1.92" (uid=0 pid=7863 comm="/usr/bin/python Divers/tst_dbus.py ") interface="(unset)" member="getProperties" error name="(unset)" requested_reply="0" destination="org.freedesktop.DBus" (bus)
# props = bus.getProperties()

itf = dbus.Interface(proxy, 'org.freedesktop.DBus')

# Does not understand message getProperties
# itf.getProperties()

theBus = dbus.Bus()
lstNam = theBus.list_names()

for nam in lstNam:

	if nam in (":1.99" ):
		continue

	try:
		ownr = theBus.get_name_owner(nam)
	except ValueError:
		ownr = nam

	try:
		pid = str(itf.GetConnectionUnixProcessID(nam))
		uid = itf.GetConnectionUnixUser(nam)
	except dbus.exceptions.DBusException:
		# Apparently happens with the first line.
		continue

	usrnam = pwd.getpwuid( uid ).pw_name

	sys.stdout.write( " %-30s %10s %20s own=%s\n" % ( nam, pid, usrnam, ownr ) )


