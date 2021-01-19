"""
Desktop Bus connection
"""

import sys
import pwd
import logging
import lib_dbus
import lib_common
import dbus
from lib_properties import pc


def EntityOntology():
    return (["Bus", "Connect"],)


def AddInfo(grph, node, entity_ids_arr):
    """This must add information about the dbus connection.
    Example: entity_id=['system', 'org.freedesktop.UDisks2']
    """
    # sys.stderr.write("AddInfo entity_id=%s\n" % str(entity_ids_arr) )

    try:
        bus_addr = entity_ids_arr[0]
        # sys.stderr.write("AddInfo bus_addr=%s\n" % bus_addr)
        the_bus = lib_dbus.MakeBusFromAddress(bus_addr)

        connct_nam = entity_ids_arr[1]
        # sys.stderr.write("AddInfo connct_nam=%s\n" % connct_nam)

        proxy=the_bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        # sys.stderr.write("AddInfo proxy=%s\n" % str(proxy))

        # itf = proxy
        itf = dbus.Interface(proxy, 'org.freedesktop.DBus')

        pid = str(itf.GetConnectionUnixProcessID(connct_nam))
        uid = itf.GetConnectionUnixUser(connct_nam)
        # sys.stderr.write("AddInfo pid=%s uid=%s\n" % (pid, uid))
    except dbus.exceptions.DBusException as exc:
        # Could be: "org.freedesktop.DBus.Error.AccessDenied"
        logging.warning("AddInfo Caught=%s", str(exc))
        # Apparently happens with the first line.
        return
    usrnam = pwd.getpwuid(uid).pw_name

    node_proc = lib_common.gUriGen.PidUri(pid)
    node_user = lib_common.gUriGen.UserUri(usrnam)
    grph.add((node, pc.property_pid, node_proc))
    grph.add((node, pc.property_user, node_user))

