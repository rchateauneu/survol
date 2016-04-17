#!/usr/bin/python

import os
import re
import sys
import psutil
import socket
import urllib
import cgi       # One of the CGI arguments is the name of the shared library.

import rdflib
from rdflib import Literal

import lib_common
from lib_common import pc

def DoNothing():
	return

def AddDepends(library):
	libNode = lib_common.SharedLibUri( library )
	grph.add( ( nodeSharedLib, pc.property_library_depends, libNode ) )

grph = rdflib.Graph()

# fileSharedLib = "/usr/lib/libxmlrpc++.so"
# This can be srun from the command line like this:
# QUERY_STRING="SHAREDLIB=/usr/lib/libkdecore.so" htbin/sources/cgi_linux_nm.py
# The url must be encoded at this stage.

arguments = cgi.FieldStorage()
try:
	fileSharedLib = arguments["entity_id"].value
except KeyError:
	lib_common.ErrorMessageHtml("Must provide an shared library")

# Maybe the file does not contain its path so it must be added.
if ( fileSharedLib[0] != '/' ):
	fileSharedLib = os.getcwd() + '/' + fileSharedLib

nodeSharedLib = lib_common.SharedLibUri( fileSharedLib )

stream = os.popen("ldd " + fileSharedLib)

# Line read are such as: 
#        linux-gate.so.1 =>  (0xffffe000)
#        libdl.so.2 => /lib/libdl.so.2 (0xb7dae000)
#        libc.so.6 => /lib/i686/libc.so.6 (0xb7c6a000)
#        /lib/ld-linux.so.2 (0x80000000)
# Do not know what to do with the lines without an arrow.
# Do not know what happens if a library name contains a space.
rgx = re.compile('^.*=> *([^ ]+) \(')

for line in stream:
	matchObj = re.match( rgx, line )
	if matchObj:
		AddDepends( matchObj.group(1) )

# The dependencies are flattened which may be is a mistake.

lib_common.OutCgiRdf(grph)


