"""
Python package
"""

import os
import sys
import pip
import importlib
import lib_common
import lib_uris
import lib_util
import lib_python
from lib_properties import pc

try:
	import modulefinder
except ImportError:
	pass


# TODO: Should do that only when executing ?? How to make the difference ??
propPythonVersion = lib_common.MakeProp("Version")
propPythonRequires = lib_common.MakeProp("Requires")
propPythonPackage = lib_common.MakeProp("Package")

def EntityOntology():
	return ( ["Id"], )

# TODO: Is the caption the best key ? Also: It should dependd on the Python version.
def MakeUri(packageKey):
	return lib_common.gUriGen.UriMake("python/package",packageKey)

# Display information about a Python package using what is returned by PIP.
def FillOnePackage(grph,node,good_pckg):
	# >>> dir(installed_packages[0])
	# ['PKG_INFO', '__class__', '__delattr__', '__dict__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__',
	#  '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__',
	#  '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_dep_map', '_get_metadata', '_key', '_provider', '_relo
	# ad_version', '_version', '_warn_legacy_version', 'activate', 'as_requirement', 'check_version_conflict', 'clone', 'egg_name', 'extra
	# s', 'from_filename', 'from_location', 'get_entry_info', 'get_entry_map', 'has_version', 'hashcmp', 'insert_on', 'key', 'load_entry_p
	# oint', 'location', 'parsed_version', 'platform', 'precedence', 'project_name', 'py_version', 'requires', 'version']

	grph.add( (node, propPythonVersion, lib_common.NodeLiteral(good_pckg.version) ) )
	grph.add( (node, lib_common.MakeProp("Platform"), lib_common.NodeLiteral(good_pckg.platform) ) )
	grph.add( (node, lib_common.MakeProp("project_name"), lib_common.NodeLiteral(good_pckg.project_name) ) )

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
			grph.add( (subNode, lib_common.MakeProp("Condition"), lib_common.NodeLiteral( str(aSpecs) ) ) )
		grph.add( (node, lib_common.MakeProp("requires"), subNode ) )

	grph.add( (node, lib_common.MakeProp("py_version"), lib_common.NodeLiteral(good_pckg.py_version) ) )
	grph.add( (node, lib_common.MakeProp("precedence"), lib_common.NodeLiteral(good_pckg.precedence) ) )
	grph.add( (node, lib_common.MakeProp("egg_name"), lib_common.NodeLiteral(good_pckg.egg_name()) ) )

	# This might return location="c:\python27\lib\site-packages"
	cleanLocaDir = good_pckg.location.replace("\\","/")
	nodeLocation = lib_common.gUriGen.DirectoryUri(cleanLocaDir)
	grph.add( (node, lib_common.MakeProp("Location"),nodeLocation ) )


# http://stackoverflow.com/questions/247770/retrieving-python-module-path
#import imp
#imp.find_module("os")
#It gives a tuple with the path in second position:
#(<open file '/usr/lib/python2.7/os.py', mode 'U' at 0x7f44528d7540>,
#'/usr/lib/python2.7/os.py',
#('.py', 'U', 1))


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfoFromPip(grph,node,packageKey):
	try:
		# TODO: What about several Python versions ?
		installed_packages = lib_python.PipGetInstalledDistributions()

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
							grph.add( (node, lib_common.MakeProp("Condition "+pckg.key), lib_common.NodeLiteral( str(aSpecs) ) ) )
						grph.add( (subNode, propPythonRequires, node ) )
						break

	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, lib_common.NodeLiteral(str(exc)) ) )

# Displays general information about the module.
def AddInfoFromImport(grph,packageNode,packageKey):
	try:
		the_module = importlib.import_module( packageKey )
	except ImportError:
		lib_common.ErrorMessageHtml("Importing %s: Error %s" % ( packageKey, str( sys.exc_info() ) ) )

	try:
		initFilNam = the_module.__file__
		filNode = lib_common.gUriGen.FileUri(initFilNam)
		grph.add( ( packageNode, propPythonPackage, filNode ) )

	except AttributeError:
		pass

	try:
		txtDoc = the_module.__doc__
		if txtDoc:
			grph.add( ( packageNode, pc.property_information, lib_common.NodeLiteral(txtDoc) ) )
	except AttributeError:
		pass

	propsPackage = {"Author" : "__author__", "Version" : "__version__"}

	for keyProp in propsPackage:
		valProp = propsPackage[keyProp]
		try:
			txtVal = getattr( the_module, valProp )
			if txtVal:
				grph.add( ( packageNode, lib_common.MakeProp(keyProp), lib_common.NodeLiteral(txtVal) ) )
		except AttributeError:
			pass

def AddInfo(grph,node,entity_ids_arr):
	packageKey = entity_ids_arr[0]
	sys.stderr.write("AddInfo packageKey=%s\n"%packageKey)

	AddInfoFromPip(grph,node,packageKey)

	AddInfoFromImport(grph,node,packageKey)



# This adds to a node representing a Python package,
# a node for each package recursively imported by this one.
# TODO: At the moment, this is NOT RECURSIVE !!!
def AddImportedModules(grph,node,filNam,maxDepth,dispPackages,dispFiles):
	sys.stderr.write("AddImportedModules filNam=%s dispPackages=%d dispFiles=%d\n"%(filNam,dispPackages,dispFiles))
	filename, file_extension = os.path.splitext(filNam)
	filextlo = file_extension.lower()
	if filextlo not in [".py",".pyw"]:
		return

	finder = modulefinder.ModuleFinder()
	try:
		finder.run_script(filNam)
	except TypeError:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("Error loading Python script %s:%s" % ( filNam, str( exc ) ) )

	AddImportedModules.dictModules = dict()

	# A cache which associates a node to a Python module name.
	def GetModuNode(moduNam):
		try:
			moduNode = AddImportedModules.dictModules[moduNam]
		except KeyError:
			moduNode = MakeUri( moduNam )
			AddImportedModules.dictModules[moduNam] = moduNode
		return moduNode

	AddImportedModules.dictFiles = dict()

	# A cache which associates a node to a file name.
	def GetFileNode(moduFil):
		try:
			fileNode = AddImportedModules.dictModules[moduFil]
		except KeyError:
			fileNode = lib_uris.gUriGen.FileUri(moduFil)
			AddImportedModules.dictModules[moduFil] = fileNode
		return fileNode

	for moduNam, mod in lib_util.six_iteritems( finder.modules ):
		splitNam = moduNam.split(".")
		# sys.stderr.write("splitNam=%s\n"%str(splitNam))
		# sys.stderr.write("mod=%s\n"%str(mod))
		moduFil = mod.__file__
		# sys.stderr.write("moduFil=%s\n"%moduFil)

		if len(splitNam) > maxDepth:
			continue

		if dispPackages:
			moduNod = GetModuNode(moduNam)

			if dispFiles and moduFil:
				nodeFile = GetFileNode(moduFil)
				# nodeFile is the result of lib_common.NodeUrl
				grph.add( ( moduNod, pc.property_rdf_data_nolist2, nodeFile ) )

			if len(splitNam) == 1:
				grph.add( ( node, propPythonPackage, moduNod ) )
				sys.stderr.write("No parent: moduNam=%s\n"%(moduNam))
			else:
				parentModuNam = ".".join(splitNam[:-1])
				parentModuNod = GetModuNode(parentModuNam)
				grph.add( ( parentModuNod, propPythonRequires, moduNod ) )
				sys.stderr.write("parentModuNam=%s moduNam=%s\n"%(parentModuNam,moduNam))

		if dispFiles and not dispPackages:
			if moduFil:
				nodeFile = GetFileNode(moduFil)
				if len(splitNam) == 1:
					# TODO: Should be connected to the module.
					grph.add( ( node, propPythonPackage, nodeFile ) )
					# TODO: LE RAJOUTER QUAND MEME SINON ON NE VOIT RIEN !
					pass
				else:
					parentModuNam = ".".join(splitNam[:-1])
					parentModuNod = GetModuNode(parentModuNam)
					grph.add( ( parentModuNod, propPythonRequires, nodeFile ) )


