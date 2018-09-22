"""
Python language concepts
"""

import os
import sys
import lib_uris
import lib_common

pyExtensions = {
	".py" : "Python source",
	".pyw": "Python Windows source",
	".pyc": "Compiled Python",
	".pyo": "Optimised compiled Python",
	".pyd": "Python DLL"}

# A Python file is associated to the corresponding *.pyc etc...
# This adds a link to all files in the same directory which has the same name,
# if the extension is a Python one.
def AddAssociatedFiles(grph,node,filNam):
	DEBUG("AddAssociatedFiles %s",filNam)
	# sys.stderr.write("filNam=%s\n"%filNam)
	filenameNoExt, file_extension = os.path.splitext(filNam)

	for ext in pyExtensions:
		filAssocNam = filenameNoExt + ext

		sys.stderr.write("filAssocNam=%s filNam=%s\n"%(filAssocNam,filNam))
		# Do not add a link to itself. Beware: Not reliable on Linux because of case sensitivities.
		if filAssocNam.lower() != filNam.lower():
			if os.path.isfile(filAssocNam):
				sys.stderr.write("Link filAssocNam=%s filNam=%s\n"%(filAssocNam,filNam))
				filAssocNode = lib_uris.gUriGen.FileUri(filAssocNam)
				grph.add( ( node, lib_common.MakeProp(pyExtensions[ext]), filAssocNode ) )


