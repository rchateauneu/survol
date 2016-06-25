import os
import sys
import json
import lib_util

def CredFilNam():
	dirNam = lib_util.gblTopScripts
	# dirNam = lib_common.pathRoot
	# filNam = "C:/Users/rchateau/SurvolCredentials.json"
	filNam = dirNam + "/../../SurvolCredentials.json"
	sys.stderr.write("CredFilNam %s\n"%filNam)
	return filNam

def CredDocument():
	filNam = CredFilNam()
	credentials = json.load( open(filNam) )
	return credentials

# Loaded once only.
credentials = CredDocument()

def GetCredentials( credType, credName ):
	try:
		arrType = credentials[credType]
		try:
			cred = arrType[credName]
			sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
			return cred
		except KeyError:
			sys.stderr.write("GetCredentials Unknown name credType=%s credName=%s\n" % (credType,credName))
			return ('','')
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s credName=%s\n" % (credType,credName))
		return None

def GetCredentialsNames( credType ):
	try:
		arrType = credentials[credType]
		return arrType.keys()
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s\n" % (credType))
		return None

