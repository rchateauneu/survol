#!/usr/bin/python

import os
import sys
import rdflib
import dbus
import lib_common
import lib_util
import lib_dbus
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	cgiEnv = lib_common.CgiEnv("Interfaces of a DBUS object")
	connectionName = cgiEnv.GetId()

	grph = rdflib.Graph()

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
