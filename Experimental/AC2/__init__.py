"""
AC2 classes
"""

import os
import lib_common

envVarNam = "XCOMP_AC2_BASE"

def Usable(entity_type,entity_ids_arr):
	"""
	The environment variable XCOMP_AC2_BASE must be defined
	"""
	try:
		ac2TopDir = os.environ[envVarNam]
		return True
	except:
		return False
		lib_common.ErrorMessageHtml("Cannot get environment variable value %s"%envVarNam )


def Graphic_shape():
	return "none"

def Graphic_colorfill():
	return "#88BBFF"

def Graphic_colorbg():
	return "#88BBFF"

def Graphic_border():
	return 0

def Graphic_is_rounded():
	return True



def ConfigFileNameClean(configFilename):
	onlyFile = os.path.basename(configFilename)

	filNoExt = os.path.splitext(onlyFile)[0]
	return filNoExt

# propComp2App = lib_common.MakeProp("application",direction="bidirectional")
propComp2App = lib_common.MakeProp("application")
propCronRules = lib_common.MakeProp("Cron rules")
propTrigger = lib_common.MakeProp("Trigger")
propComponents = lib_common.MakeProp("components")
propParent = lib_common.MakeProp("parent")


