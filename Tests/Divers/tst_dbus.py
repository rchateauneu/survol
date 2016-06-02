#!/usr/bin/python

# http://www.mattfischer.com/blog/?p=494

import dbus
import sys
# Linux specific.
import pwd

system_bus=dbus.SystemBus()
proxy=system_bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')

# dbus.exceptions.DBusException: org.freedesktop.DBus.Error.AccessDenied: Rejected send message, 7 matched rules; type="method_call", sender=":1.92" (uid=0 pid=7863 comm="/usr/bin/python Divers/tst_dbus.py ") interface="(unset)" member="getProperties" error name="(unset)" requested_reply="0" destination="org.freedesktop.DBus" (bus)
# props = bus.getProperties()

itf = dbus.Interface(proxy, 'org.freedesktop.DBus')

# Does not understand message getProperties
# itf.getProperties()

def Test1():
	itfLstNams = itf.ListNames()
	print("Listnames : %d" % ( len(itfLstNams) ) )
	for nam in itfLstNams:
		try:
			pid = str(itf.GetConnectionUnixProcessID(nam))
			uid = itf.GetConnectionUnixUser(nam)
		except dbus.exceptions.DBusException:
			# Apparently happens with the first line.
			continue

		usrnam = pwd.getpwuid( uid ).pw_name

		ownr = itf.GetNameOwner(nam)
		print( " %-30s %10s %20s own=%s" % ( nam, pid, usrnam, ownr ) )

		for connct in itf.ListQueuedOwners(nam):
			if connct != nam:
				print("    "+connct)


####################################

# bus=dbus.SystemBus().get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')

def Test2():
	print("")
	theBus = dbus.Bus()
	lstNam = theBus.list_names()
	print("lst_names: %d items" % len(lstNam) )
	for nam in lstNam:
		try:
			own = theBus.get_name_owner(nam)
			ourHasOwn = True
		except ValueError:
			ourHasOwn = False

		theirHasOwn = theBus.name_has_owner(nam)

		if ourHasOwn:
			print("%-20s own=%s" % ( nam, own ) )
		else:
			print("%-20s" % ( nam ) )

		# if ourHasOwn != theirHasOwn:
		# 	print("INCONSISTENCY: %s %s" % ( str(ourHasOwn), str(theirHasOwn) ) )

####################################

def Test2():
	print("")
	lstActNam = theBus.list_activatable_names()
	print("lst_activatable_names: %d items" % len(lstActNam) )
	for nam in lstActNam:
		try:
			own = theBus.get_name_owner(nam)
			ourHasOwn = True
		except ValueError:
			ourHasOwn = False
		except dbus.exceptions.DBusException:
			# org.freedesktop.DBus.Error.NameHasNoOwner: Could not get owner of name 'org.freedesktop.Telepathy.Client.KTp.ConfAuthObserver'
			ourHasOwn = False

		theirHasOwn = theBus.name_has_owner(nam)

		if ourHasOwn:
			print("%-20s own=%s" % ( nam, own ) )
		else:
			print("%-20s" % ( nam ) )

####################################
# http://dbus.freedesktop.org/doc/dbus-python/doc/tutorial.html


#print("")
#
#bus = dbus.SystemBus()
#eth0 = bus.get_object('org.freedesktop.NetworkManager',
#                      '/org/freedesktop/NetworkManager/Devices/eth0')
#eth0_dev_iface = dbus.Interface(eth0,
#    dbus_interface='org.freedesktop.NetworkManager.Devices')
#props = eth0_dev_iface.getProperties()



####################################
# https://en.wikibooks.org/wiki/Python_Programming/Dbus


#bus = dbus.SystemBus()
#hal_manager_object = bus.get_object('org.freedesktop.Hal', '/org/freedesktop/Hal/Manager')
#hal_manager_interface = dbus.Interface(hal_manager_object, 'org.freedesktop.Hal.Manager')
#
# calling method upon interface
#print hal_manager_interface.GetAllDevices()
#
# accessing a method through 'get_dbus_method' through proxy object by specifying interface
#method = hal_manager_object.get_dbus_method('GetAllDevices', 'org.freedesktop.Hal.Manager')
#print method()
#
# calling method upon proxy object by specifying the interface to use
#print hal_manager_object.GetAllDevices(dbus_interface='org.freedesktop.Hal.Manager')

####################################

# AccessDenied
#itf_intro = dbus.Interface(proxy, dbus.INTROSPECTABLE_IFACE )
#interface = itf_intro.Introspect()
#print interface
#
#print str( proxy.ListNames() )
#print str( proxy.ListActivatableNames() )

####################################

# http://unix.stackexchange.com/questions/203410/how-to-list-all-object-paths-under-a-dbus-service

from xml.etree import ElementTree

def rec_intro(bus, service, object_path):
	yield object_path
	obj = bus.get_object(service, object_path)
	iface = dbus.Interface(obj, 'org.freedesktop.DBus.Introspectable')
	xml_string = iface.Introspect()

	print("::: "+ object_path + "\n" + xml_string)
	for child in ElementTree.fromstring(xml_string):
		print("+++++++ "+child.tag)
		if child.tag == 'node':
			if object_path == '/':
				object_path = ''
			new_path = '/'.join((object_path, child.attrib['name']))
			# In Python 3.3 this can be replaced by "yield from"
			for recuObj in rec_intro(bus, service, new_path):
				yield recuObj
		elif child.tag == 'interface':
			itfNam = child.attrib['name']
			print( "________ "+ itfNam )
			# for mth in child.findall("node/interface/method"):
			for mth in child.findall("method"):
				mthNam = mth.attrib['name']
				if mthNam == "GetAll":
					print("____________ Mth="+mthNam)
					# ifaceGetAll = dbus.Interface(obj,itfNam)
					theItfProp = "org.freedesktop.DBus.Properties"
					# theItf = "org.gtk.vfs.mounttracker"
					# theItf = "org.gtk.vfs.Daemon"
					theItf = theItfProp
					theItfShort = ".".join( object_path.split("/")[1:4] )
					theItf = ".".join( object_path.split("/")[1:] )
					ifaceGetAll = dbus.Interface(obj, dbus_interface=theItfProp)
					# ifaceGetAll = dbus.Interface(obj, dbus_interface=theItfShort)
					print( "______________ path="+ object_path )
					print( "______________ itfShould="+ str(ifaceGetAll) )
					print( "______________ itfActual="+ str(theItf) )
					try:
						# C est la qu on a le plus de resultats.
						xxx = ifaceGetAll.GetAll(theItf)
						# xxx = ifaceGetAll.GetAll(theItfProp)
						print("xxx="+str(xxx))
					except dbus.exceptions.DBusException as exc:
						print("Caught DBusException(1):"+str(exc))
						continue

print("")


#if "a" == "c":
#	theBus = dbus.Bus()
#	lstNam = theBus.list_names()
#elif "a" == "b":
#	theBus = dbus.SystemBus()
#	lstNam = theBus.list_names()
#else:
#	theBus = dbus.SystemBus()
#	proxy=theBus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
#	itf = dbus.Interface(proxy, 'org.freedesktop.DBus')
#	lstNam = itf.ListNames()

theBus = dbus.Bus()
lstNam = theBus.list_names()

for nam in lstNam:

	if nam in (":1.99" ):
		continue

	print("")
	print("")
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

	print( " %-30s %10s %20s own=%s" % ( nam, pid, usrnam, ownr ) )

	# listobjs = rec_intro(theBus, nam, ServiceToObj(nam) )
	try:
		listobjs = rec_intro(theBus, nam, "/" )
		for ob in listobjs:
			if ob in ("/",""):
				continue
			print( ob + ".")
	except dbus.exceptions.DBusException as exc:
		print("Caught DBusException:"+str(exc))
	except dbus.proxies as exc:
		print("Caught proxies:"+str(exc))


itf = dbus.Interface(proxy, 'org.freedesktop.DBus')
itfLstNams = itf.ListNames()




