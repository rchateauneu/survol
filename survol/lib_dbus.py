import lib_util
import dbus
import sys
import logging

# Bus / address              : "unix:path=/var/run/dbus/system_bus_socket"
# Connection / bus name      : ":34-907" (unique) or "com.mycompany.TextEditor (well-known)"
# Object / path              : "/com/mycompany/TextFileManager"
# Interface / interface name :  "org.freedesktop.Hal.Manager"
# Member / member name       : ListNames()

 

def MakeBusFromAddress( busAddr ):
	logging.debug("MakeBusFromAddress busAddr=%s", busAddr )
	if busAddr == "system":
		return dbus.SystemBus()
	if busAddr == "session":
		return dbus.SessionBus()

	return dbus.Bus( busAddr )
