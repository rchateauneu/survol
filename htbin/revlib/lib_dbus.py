import lib_util
import dbus
import sys

# Bus / address              : "unix:path=/var/run/dbus/system_bus_socket"
# Connection / bus name      : ":34-907" (unique) or "com.mycompany.TextEditor (well-known)"
# Object / path              : "/com/mycompany/TextFileManager"
# Interface / interface name :  "org.freedesktop.Hal.Manager"
# Member / member name       : ListNames()

 

def MakeBusFromAddress( busAddr ):
	sys.stderr.write("MakeBusFromAddress busAddr=%s\n" % busAddr )
	if busAddr == "system":
		return dbus.SystemBus()
	if busAddr == "session":
		return dbus.SessionBus()

	return dbus.Bus( busAddr )
