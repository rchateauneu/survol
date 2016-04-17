#!/usr/bin/python

# Does not do anything yet.

# http://technet.microsoft.com/fr-fr/sysinternals/bb896682.aspx
# On pourrait peut-etre utiliser Wine ?
# On a essaye, ca ne marche pas.

import lib_common

import psutil
import socket
import rdflib
from lib_common import pc

grph = rdflib.Graph()

lib_common.OutCgiRdf(grph)

