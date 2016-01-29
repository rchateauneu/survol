#!/usr/bin/python

import re
import os
import sys
import subprocess
import pysmb

import rdflib

import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv()
# Top directory, not just the share name.
# smbFile= cgiEnv.GetId("//DUOLNX/IncomingCopied/")
smbFile= cgiEnv.GetId()

nodeSmbShr = lib_common.gUriGen.SmbServerUri( smbServer )

# Not finished.

# AUCUNE IDEE SI C EST POSSIBLE DE LISTER LES SHARES D'UN SERVER ,
# DONC LA SUITE EST FAUSSE.

for x in z:
	shareNode = lib_common.gUriGen.SmbShareUri( "//" + smbServer + "/" + x )

	grph.add( ( nodeSmbShr, pc.property_smbshare, shareNode ) )







