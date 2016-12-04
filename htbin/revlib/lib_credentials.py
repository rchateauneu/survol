import os
import sys
import json
import lib_util

# TODO: Several accesses per machine or database ?
# TODO: What if an access for "192.168.1.78" and "titi" ?

def CredFilNam():
	dirNam = lib_util.gblTopScripts
	# dirNam = lib_common.pathRoot
	# dirNam=C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle//htbin

	# filNam = "C:\Users\rchateau\Developpement\ReverseEngineeringApps\SurvolCredentials.json"
	filNam = dirNam + "/../../SurvolCredentials.json"

	# C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/htbin/../../SurvolCredentials.json
	# sys.stderr.write("CredFilNam dirNam=%s %s\n"%(dirNam,filNam))
	return filNam

def CredDocument():
	filNam = CredFilNam()
	try:
		credentials = json.load( open(filNam) )
		# sys.stderr.write("CredDocument credentials=%d elements\n" % (len(credentials)))
		return credentials
	except Exception:
		sys.stderr.write("CredDocument no credentials: %s\n" % str(sys.exc_info()))
		return dict()

# Loaded once only.
credentials = CredDocument()

# For example: GetCredentials("Oracle","XE") or GetCredentials("Login","192.168.1.78")
# It returns the username and the password.
def GetCredentials( credType, credName ):
	#sys.stderr.write("GetCredentials credType=%s credName=%s credentials=%d elements\n" % (credType,credName,len(credentials)))
	try:
		if not credentials:
			return ('','')
		arrType = credentials[credType]
		try:
			cred = arrType[credName]
			#sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
			return cred
		except KeyError:
			#sys.stderr.write("GetCredentials Unknown name credType=%s credName=%s\n" % (credType,credName))
			return ('','')
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s credName=%s\n" % (credType,credName))
		return None

# For example, if "credType" == "Oracle", it will returned all databases defined in the credentials file.
# TODO: For Oracle, consider exploring tnsnames.ora ?
def GetCredentialsNames( credType ):
	try:
		arrType = credentials[credType]
		return arrType.keys()
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s\n" % (credType))
		return None

