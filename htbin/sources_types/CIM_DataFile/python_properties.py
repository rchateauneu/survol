#!/usr/bin/python

"""
Python properties
"""

import os
import os.path
import sys
import six
import rdflib
import lib_util
import lib_uris
import lib_common
from lib_properties import pc

from sources_types import python
from sources_types.python import package

try:
	import modulefinder
except ImportError:
	pass

pyExtensions = {
	".py" : "Python source",
	".pyc": "Compiled Python",
	".pyo": "Optimised compiled Python",
	".pyd": "Python DLL"}

def Usable(entity_type,entity_ids_arr):
	"""Can run with Python files only"""

	filNam = entity_ids_arr[0]

	# But probably it is not enough and we should try to open it.
	filExt = os.path.splitext(filNam)[1]
	return filExt.lower() in pyExtensions

# A Python file is associetd to the corresponding *.pyc etc...
def AddAssociatedFiles(grph,node,filNam):
	sys.stderr.write("AddAssociatedFiles %s\n"%(filNam))
	# sys.stderr.write("filNam=%s\n"%filNam)
	filenameNoExt, file_extension = os.path.splitext(filNam)

	for ext in pyExtensions:
		filAssocNam = filenameNoExt + ext

		sys.stderr.write("filAssocNam=%s filNam=%s\n"%(filAssocNam,filNam))
		if filAssocNam.lower() != filNam.lower():
			if os.path.isfile(filAssocNam):
				sys.stderr.write("Link filAssocNam=%s filNam=%s\n"%(filAssocNam,filNam))
				filAssocNode = lib_uris.gUriGen.FileUri(filAssocNam)
				grph.add( ( node, lib_common.MakeProp(pyExtensions[ext]), filAssocNode ) )

def AddImportedModules(grph,node,filNam,maxDepth,dispPackages,dispFiles):
	sys.stderr.write("AddImportedModules filNam=%s dispPackages=%d dispFiles=%d\n"%(filNam,dispPackages,dispFiles))
	filename, file_extension = os.path.splitext(filNam)
	filextlo = file_extension.lower()
	if filextlo != ".py":
		return

	finder = modulefinder.ModuleFinder()
	try:
		finder.run_script(filNam)
	except TypeError:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("Error loading Python script %s:%s" % ( filNam, str( exc ) ) )

	AddImportedModules.dictModules = dict()

	def GetModuNode(moduNam):
		try:
			moduNode = AddImportedModules.dictModules[moduNam]
		except KeyError:
			moduNode = package.MakeUri( moduNam )
			AddImportedModules.dictModules[moduNam] = moduNode
		return moduNode

	AddImportedModules.dictFiles = dict()

	def GetFileNode(moduFil):
		try:
			fileNode = AddImportedModules.dictModules[moduFil]
		except KeyError:
			fileNode = lib_uris.gUriGen.FileUri(moduFil)
			AddImportedModules.dictModules[moduFil] = fileNode
		return fileNode

	for moduNam, mod in six.iteritems( finder.modules ):
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
				# grph.add( ( moduNod, package.propPythonRequires, nodeFile ) )
				# nodeFile is the result of rdflib.term.URIRef
				grph.add( ( moduNod, pc.property_rdf_data_nolist2, nodeFile ) )

			if len(splitNam) == 1:
				grph.add( ( node, package.propPythonPackage, moduNod ) )
				sys.stderr.write("No parent: moduNam=%s\n"%(moduNam))
			else:
				parentModuNam = ".".join(splitNam[:-1])
				parentModuNod = GetModuNode(parentModuNam)
				grph.add( ( parentModuNod, package.propPythonRequires, moduNod ) )
				sys.stderr.write("parentModuNam=%s moduNam=%s\n"%(parentModuNam,moduNam))

		if dispFiles and not dispPackages:
			if moduFil:
				nodeFile = GetFileNode(moduFil)
				if len(splitNam) == 1:
					# TODO: Should be connected to the module.
					grph.add( ( node, package.propPythonPackage, nodeFile ) )
					# TODO: LE RAJOUTER QUAND MEME SINON ON NE VOIT RIEN !
					pass
				else:
					parentModuNam = ".".join(splitNam[:-1])
					parentModuNod = GetModuNode(parentModuNam)
					grph.add( ( parentModuNod, package.propPythonRequires, nodeFile ) )

def Main():
	paramkeyMaxDepth = "Maximum depth"
	paramkeyDispPackages = "Display packages"
	paramkeyDispFiles = "Display files"

	cgiEnv = lib_common.CgiEnv(
			{ paramkeyMaxDepth : 1, paramkeyDispPackages: True, paramkeyDispFiles: False} )

	maxDepth = cgiEnv.GetParameters( paramkeyMaxDepth )
	dispPackages= cgiEnv.GetParameters( paramkeyDispPackages )
	dispFiles = cgiEnv.GetParameters( paramkeyDispFiles )

	pyFilNam = cgiEnv.GetId()

	# sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

	grph = rdflib.Graph()

	filNode = lib_common.gUriGen.FileUri(pyFilNam)

	try:

		AddAssociatedFiles(grph,filNode,pyFilNam)
	except:
		exc = sys.exc_info()[0]
		lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( pyFilNam, str( exc ) ) )
	AddImportedModules(grph,filNode,pyFilNam,maxDepth,dispPackages,dispFiles)

	cgiEnv.OutCgiRdf(grph,"LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()
