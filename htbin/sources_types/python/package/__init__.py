import sys
import rdflib
import psutil
import lib_common
import lib_util
from lib_properties import pc

import pip
from sources_types import python

import lib_common

# TODO: Should do that only when excecuting ?? How to make the difference ??
propPythonVersion = lib_common.MakeProp("Version")
propPythonRequires = lib_common.MakeProp("Requires")
propPythonPackage = lib_common.MakeProp("Package")


# TODO: Is the caption the best key ?
def MakeUri(packageKey):
	return lib_common.gUriGen.UriMake("python/package",packageKey)

# New style of entity-specific code which is now in the
# module ENTITY.py instead of lib_entities/lib_entity_ENTITY.py
# which was not a very 'pythonic' architecture.

def FillOnePackage(grph,node,good_pckg):
	# >>> dir(installed_packages[0])
	# ['PKG_INFO', '__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
	#  '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
	#  '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_dep_map', '_get_metadata', '_key', '_provider', '_relo
	# ad_version', '_version', '_warn_legacy_version', 'activate', 'as_requirement', 'check_version_conflict', 'clone', 'egg_name', 'extra
	# s', 'from_filename', 'from_location', 'get_entry_info', 'get_entry_map', 'has_version', 'hashcmp', 'insert_on', 'key', 'load_entry_p
	# oint', 'location', 'parsed_version', 'platform', 'precedence', 'project_name', 'py_version', 'requires', 'version']

	grph.add( (node, propPythonVersion, rdflib.Literal(good_pckg.version) ) )
	grph.add( (node, lib_common.MakeProp("Platform"), rdflib.Literal(good_pckg.platform) ) )
	grph.add( (node, lib_common.MakeProp("project_name"), rdflib.Literal(good_pckg.project_name) ) )

	# >>> pip.get_installed_distributions()[1].requires()
	# [Requirement.parse('distribute'), Requirement.parse('werkzeug'), Requirement.parse('mako')]
	# '_Requirement__hash', '__contains__','__doc__', '__eq__', '__hash__','__init__', '__module__', '__ne__',
	# '__repr__', '__str__', 'extras','hashCmp', 'key', 'marker_fn', 'parse','project_name', 'specifier', 'specs','unsafe_name'
	# strReq = "+".join( [ str(dir(req)) for req in good_pckg.requires() ])

	for subReq in good_pckg.requires():
		subNode = MakeUri( subReq.key )
		# [('>=', '4.0.0')]+[]+[('>=','4.0')]+[]
		aSpecs = subReq.specs
		if aSpecs:
			grph.add( (subNode, lib_common.MakeProp("Condition"), rdflib.Literal( str(aSpecs) ) ) )
		grph.add( (node, lib_common.MakeProp("requires"), subNode ) )

	grph.add( (node, lib_common.MakeProp("py_version"), rdflib.Literal(good_pckg.py_version) ) )
	grph.add( (node, lib_common.MakeProp("precedence"), rdflib.Literal(good_pckg.precedence) ) )
	grph.add( (node, lib_common.MakeProp("egg_name"), rdflib.Literal(good_pckg.egg_name()) ) )

	# This might return location="c:\python27\lib\site-packages"
	# completeLocation = good_pckg.location.replace("\\","/") + "/" + good_pckg.project_name
	# nodeLocation = lib_common.gUriGen.FileUri(completeLocation)
	# nodeLocation = lib_common.gUriGen.FileUri(good_pckg.location)
	# This might return location="c:\python27\lib\site-packages"
	cleanLocaDir = good_pckg.location.replace("\\","/")
	nodeLocation = lib_common.gUriGen.DirectoryUri(cleanLocaDir)
	grph.add( (node, lib_common.MakeProp("Location"),nodeLocation ) )


	#grph.add( (node, lib_common.MakeProp("from_filename"), rdflib.Literal(good_pckg.from_filename()) ) )
	#grph.add( (node, lib_common.MakeProp("from_location"), rdflib.Literal(good_pckg.from_location()) ) )


# http://stackoverflow.com/questions/247770/retrieving-python-module-path
#import imp
#imp.find_module("os")
#It gives a tuple with the path in second position:
#(<open file '/usr/lib/python2.7/os.py', mode 'U' at 0x7f44528d7540>,
#'/usr/lib/python2.7/os.py',
#('.py', 'U', 1))


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	packageKey = entity_ids_arr[0]

	try:
		# TODO: What about several Python versions ?
		installed_packages = pip.get_installed_distributions()

		# TODO: Maybe the version should be part of the key.
		for pckg in installed_packages:
			if packageKey == pckg.key:
				FillOnePackage(grph, node, pckg)
			else:
				for subReq in pckg.requires():
					# sys.stderr.write("subReq.key=%s pckg.key=%s\n"%(subReq.key,packageKey))
					if subReq.key == packageKey:
						subNode = MakeUri( pckg.key )
						# [('>=', '4.0.0')]+[]+[('>=','4.0')]+[]
						aSpecs = subReq.specs
						if aSpecs:
							# TODO: This should be displayed on the edge !!!
							#grph.add( (node, lib_common.MakeProp("Condition",test=pckg.key), rdflib.Literal( str(aSpecs) ) ) )
							grph.add( (node, lib_common.MakeProp("Condition "+pckg.key), rdflib.Literal( str(aSpecs) ) ) )
						grph.add( (subNode, propPythonRequires, node ) )
						break


	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, rdflib.Literal(str(exc)) ) )



