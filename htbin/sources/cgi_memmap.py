#!/usr/bin/python

import re
import sys
import psutil
import rdflib

import lib_common
from lib_common import pc
from rdflib import URIRef, BNode, Literal

grph = rdflib.Graph()

################################################################################

uselessLinuxMaps = [ \
        '/usr/bin/kdeinit', \
        '/bin/bash', \
        '/usr/lib/gconv/gconv-modules.cache', \
        '[stack]', \
        '[vdso]', \
        '[heap]', \
        '[anon]' ]

def FilterPathLinux(path):
        # We could also check if this is really a shared library.
        # file /lib/libm-2.7.so: ELF 32-bit LSB shared object etc...
        if path.endswith(".so"):
                return False

        # Not sure about "M" and "I". Also: Should precompile regexes.
        # And if the shared file is read-only, not very interesting, probably (But it depends).
        if re.match( r'.*/lib/.*\.so\..*', path, re.M|re.I):
                return False

        if re.match( r'/usr/share/locale/.*', path, re.M|re.I):
                return False

        if re.match( r'/usr/share/fonts/.*', path, re.M|re.I):
                return False

        if re.match( r'/etc/locale/.*', path, re.M|re.I):
                return False

        if re.match( r'/var/cache/fontconfig/.*', path, re.M|re.I):
                return False

        # Specific to KDE.
        if re.match( r'/var/tmp/kdecache-.*/ksycoca', path, re.M|re.I):
                return False

        if re.match( r'/home/.*/.local/share/mime/mime.cache', path, re.M|re.I):
                return False

        if re.match( r'/usr/bin/perl.*', path, re.M|re.I):
                return False

        if path in uselessLinuxMaps:
                return False

        return True

# Avoids storing files which are accessed by one process only.
def ManageMappedMem(processNode,path):
        global grph

        # TODO: Should resolve symbolic links, first.

        if 'linux' in sys.platform:
                if not FilterPathLinux(path):
                        return


        fullPath = "//" + lib_common.hostName + "/" + path

        if fullPath in ManageMappedMem.dictFiles:
                # Creates also a node for the first process.
                previousProcessNode = ManageMappedMem.dictFiles[fullPath]
                if previousProcessNode != "Done":
                        grph.add( ( previousProcessNode, pc.property_memmap, Literal( fullPath ) ) )
                        ManageMappedMem.dictFiles[fullPath] = "Done"
                grph.add( ( processNode, pc.property_memmap, Literal( fullPath ) ) )
        else:
                # Just store the node. Will see later if accessed by more than two process.
                ManageMappedMem.dictFiles[fullPath] = processNode
ManageMappedMem.dictFiles = {}

################################################################################

# Taken from psutil

# http://code.google.com/p/psutil/issues/detail?id=444

# WILL BE ENHANCED LATER: IT WILL CONTAIN THE INODE.


################################################################################

grph.add( ( lib_common.nodeMachine, pc.property_hostname, Literal( lib_common.hostName ) ) )

def FunctionProcess(proc):
        if lib_common.UselessProc(proc):
                return

        # The process might have left in the meantime.
        pid = proc.pid

        # node_process = BNode() # a GUID is generated
        node_process = lib_common.PidUri(pid)

        all_maps = proc.get_memory_maps()
        if all_maps:
                # This takes into account only maps accessed by several processes.
                # TODO: What about files on a shared drive?
                # To make things simple, for the moment mapped memory is processed like files.

                # TODO: WAIT UNTIL WE GET THE INODE ?????????
                for map in all_maps:
                        ManageMappedMem( node_process, map.path )

for proc in psutil.process_iter():
        if sys.version_info < (3, 2):
                try:
                        FunctionProcess(proc)
                except psutil._error.AccessDenied:
                        pass
                except:
                        print("Unexpected error:", sys.exc_info()[0])
                        raise
        else:
                try:
                        FunctionProcess(proc)
                except psutil.AccessDenied:
                        pass
                except:
                        lib_common.ErrorMessageHtml("Unexpected error:" + sys.exc_info()[0])

lib_common.OutCgiRdf(grph)

