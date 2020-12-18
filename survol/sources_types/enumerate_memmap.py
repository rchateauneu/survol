#!/usr/bin/env python

"""
Shared memory segments.

System-wide shared memory segments, plus properties. DLLs and fonts are excluded.
"""

import os
import re
import sys
import psutil
import lib_util
import lib_common
from lib_properties import pc
from sources_types import CIM_Process


def filter_path_linux(path):
    """For clarity, this eliminates many memory maps."""
    useless_linux_maps = [
        '/usr/bin/kdeinit',
        '/bin/bash',
        '/usr/lib/gconv/gconv-modules.cache',
        '[stack]',
        '[vdso]',
        '[heap]',
        '[anon]' ]

    # We could also check if this is really a shared library.
    # file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
    if path.endswith(".so"):
        return False

    # Not sure about "M" and "I". Also: Should precompile regexes.
    # And if the shared file is read-only, not very interesting, probably (But it depends).
    if re.match(r'.*/lib/.*\.so\..*', path, re.M|re.I):
        return False

    if path.startswith('/usr/share/locale/'):
        return False

    if path.startswith('/usr/share/fonts/'):
        return False

    if path.startswith('/etc/locale/'):
        return False

    if path.startswith('/var/cache/fontconfig/'):
        return False

    # Specific to KDE.
    if re.match( r'/var/tmp/kdecache-.*/ksycoca', path, re.M|re.I):
        return False

    if re.match( r'/home/.*/.local/share/mime/mime.cache', path, re.M|re.I):
        return False

    if path.startswith('/usr/bin/perl'):
        return False

    if path in useless_linux_maps:
        return False

    return True


def _good_map(path):
    """Not all memory maps are displayed."""

    # TODO: Should resolve symbolic links, first.
    if lib_util.isPlatformLinux:
        if not filter_path_linux(path):
            return ""

    # DLL are not displayed, because there would be too many of them,
    # and they are read-only, therefore less interesting.
    # OLB: data types and constants referenced by MS Office components.
    # NLS: language translation information to convert between different character sets.
    # TODO: This list in a drop-down menu.
    if lib_util.isPlatformWindows:
        file_extension = os.path.splitext(path)[1]
        if file_extension.upper() in [".DLL", ".EXE", ".PYD", ".TTF", ".TTC", ".NLS", ".OLB"]:
            return ""

    # For Linux only.
    if path.endswith( "(deleted)" ):
        path = path[:-9]

    return path


def function_process(map_to_proc, proc):
    # The process might have left in the meantime.
    pid = proc.pid

    try:
        all_maps = proc.memory_maps()
    except Exception as exc:
        WARNING("get_memory_maps Pid=%d. Caught %s", pid, str(exc))
        return

    # This takes into account only maps accessed by several processes.
    # TODO: What about files on a shared drive?
    # To make things simple, for the moment mapped memory is processed like files.

    # sys.stderr.write("NbMaps=%d\n" % len(all_maps) )

    for map in all_maps:
        clean_path = _good_map(map.path)
        if clean_path == "":
            continue

        # sys.stderr.write( "Adding clean_path=%s\n" % clean_path )
        try:
            the_list = map_to_proc[clean_path]
            the_list.append(pid)
        except KeyError:
            map_to_proc[clean_path] = [pid]


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    grph.add((lib_common.nodeMachine, pc.property_hostname, lib_util.NodeLiteral(lib_util.currentHostname)))

    map_to_proc = {}

    for proc in psutil.process_iter():
        try:
            function_process(map_to_proc, proc)
        except CIM_Process.AccessDenied:
            pass
        except Exception as exc:
            lib_common.ErrorMessageHtml("Unexpected error:" + exc)
    # sys.stderr.write( "Leaving processes enumeration\n" )

    added_procs = {}

    # Now display only memory maps with more than one process linked to it.
    for map_path, proc_lst in lib_util.six_iteritems(map_to_proc):
        if len(proc_lst) <= 0:
            continue

        uri_mem_map = lib_common.gUriGen.MemMapUri(map_path)

        for pid in proc_lst:
            try:
                node_process = added_procs[pid]
            except KeyError:
                node_process = lib_common.gUriGen.PidUri(pid)
                added_procs[pid] = node_process

            grph.add((node_process, pc.property_memmap, uri_mem_map))
    # sys.stderr.write( "Leaving second maps enumeration\n" )

    # TODO: They could also be displayed based on the hierarchy of their associated file in the directory tree.

    for pid, node_process in lib_util.six_iteritems(added_procs):
        grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
