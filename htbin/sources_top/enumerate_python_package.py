#!/usr/bin/python

"""
Installed Python packages
"""

import sys
import socket
import rdflib
import psutil
import lib_util
import lib_common
from lib_properties import pc

import pip

from sources_types import python
from sources_types.python import package


# werkzeug 0.10.4 (c:\python27\lib\site-packages\werkzeug-0.10.4-py2.7.egg)
#
# >>> dir(installed_packages[0])
# ['PKG_INFO', '__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
#  '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
#  '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_dep_map', '_get_metadata', '_key', '_provider', '_relo
# ad_version', '_version', '_warn_legacy_version', 'activate', 'as_requirement', 'check_version_conflict', 'clone', 'egg_name', 'extra
# s', 'from_filename', 'from_location', 'get_entry_info', 'get_entry_map', 'has_version', 'hashcmp', 'insert_on', 'key', 'load_entry_p
# oint', 'location', 'parsed_version', 'platform', 'precedence', 'project_name', 'py_version', 'requires', 'version']

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	# TODO: What about several Python versions ?
	installed_packages = pip.get_installed_distributions()

	# TODO: Maybe the version should be part of the key.
	for pckg in installed_packages:
		sys.stderr.write("key=%s\n" % (pckg.key) )

		packageNode = package.MakeUri( pckg.key )

		grph.add( ( packageNode, lib_common.MakeProp("Version"), rdflib.Literal(pckg.version) ) )

		grph.add( ( lib_common.nodeMachine, lib_common.MakeProp("Python package"), packageNode ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()


