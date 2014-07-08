#!/usr/bin/python

import re
import subprocess
import sys
import psutil
import rdflib

import lib_common
from lib_common import pc
from rdflib import URIRef, BNode, Literal

grph = rdflib.Graph()

#on windows
#Get the fixed drives
#wmic logicaldisk get name,description
# We could also use the WMI package index but the point here
# is also to prove that as long as we return RDF data, the
# implementation details have no importance.

# What about the ftp disks 

# Nothing is done for Linux because this is a different logic,
# so there is no point emulating the same behaviour.

if 'win' in sys.platform:
    drivelist = subprocess.Popen('wmic logicaldisk get name,description,ProviderName', shell=True, stdout=subprocess.PIPE)
    drivelisto, err = drivelist.communicate()
    strlist = drivelisto
    driveLines = strlist.split(b'\n')

    # TODO: Put this in lib_common
    property_win_netdev = rdflib.term.URIRef('http://primhillcomputers.com/ontologies/win_netdev')
   
    for lin in driveLines[1:]:
        devtype = lin[0:18].decode('ascii').strip()
        devname = lin[20:21].decode('ascii')
        devprov = lin[22:].decode('ascii').strip()
        # End of the list not interesting.
        if ( devtype == "" ):
            break
        if ( devtype != "Network Connection" ):
            continue

        # This is a temporary URN. It models a Windows device.
        diskNodeName = 'urn://' + lib_common.HostName() + "/drives:" + devname
        
        # TODO: Put this in lib_common
        diskNode = rdflib.term.URIRef(diskNodeName)

        grph.add( ( diskNode, property_win_netdev, Literal( devprov ) ) )
else:
    # REPLACE THIS BY A FUNCTION PRINTING A XML DOCUMENT.
    print( "NoClue")
    print("Should print HTML message or simply nothing")


lib_common.OutCgiRdf(grph)
