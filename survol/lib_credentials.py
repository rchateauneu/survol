import os
import sys
import json
import lib_util

# TODO: Several accesses per machine or database ?
# TODO: What if an access for "192.168.1.78" and "titi" ?


def CredFilNam():
	filNamOnly = "SurvolCredentials.json"
	try:
		return os.environ["HOME"] + "/" + filNamOnly
	except KeyError:
		sys.stderr.write("HOME not defined\n")
		pass

	try:
		return os.environ["HOMEPATH"] + "\\" + filNamOnly
	except KeyError:
		sys.stderr.write("HOMEPATH not defined\n")
		pass

	dirNam = lib_util.gblTopScripts

	filNam = dirNam + "/../../" + filNamOnly

	return filNam

def BuildCredDocument():

	filNam = CredFilNam()
	try:
		jsonCreds = json.load( open(filNam) )
		# return jsonCreds
		# sys.stderr.write("CredDocument credentials=%d elements\n" % (len(credentials)))

		upperCredentials = dict()
		for keyCred in jsonCreds:
			keyVal = jsonCreds[keyCred]
			upperCredentials[keyCred] = keyVal
			# Now converts the internal keys to uppercase. This because machines name are unpredictably converted
			# to lower or upper case, or capitalised.
			# keyValUp = { subKey.upper() : keyVal[subKey] for subKey in keyVal }
			# upperCredentials[keyCred] = keyValUp

		return upperCredentials
	except Exception:
		sys.stderr.write("CredDocument no credentials: %s\n" % str(sys.exc_info()))
		return dict()

def CredDocument():
	if not CredDocument.credentials:
		CredDocument.credentials = BuildCredDocument()

	return CredDocument.credentials

CredDocument.credentials = None

# For example: GetCredentials("Oracle","XE") or GetCredentials("Login","192.168.1.78")
# It returns the username and the password.
def GetCredentials( credType, credName ):
	if credName is None:
		credName = ""
	credentials = CredDocument()
	sys.stderr.write("GetCredentials credType=%s credName=%s credentials=%d elements\n" % (credType,credName,len(credentials)))
	try:
		if not credentials:
			return ('','')
		arrType = credentials[credType]
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s credName=%s\n" % (credType,credName))
		return None

	# Try first without converting.
	try:
		cred = arrType[credName]
		sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
		return cred
	except KeyError:
		pass

	# We must convert the machine names to uppercase because this is "sometimes" done by Windows.
	# Might be a problem if several entries are identical except the case.
	keyVal = credentials[credType]
	arrTypeUpper = { subKey.upper() : keyVal[subKey] for subKey in arrType }

	credNameUpper = credName.upper()
	try:
		cred = arrTypeUpper[credNameUpper]
		sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
		return cred
	except KeyError:
		sys.stderr.write("GetCredentials Unknown name credType=%s credName=%s\n" % (credType,credName))
		return ('','')

# For example, if "credType" == "Oracle", it will returned all databases defined in the credentials file.
# TODO: For Oracle, consider exploring tnsnames.ora ?
def GetCredentialsNames( credType ):
	try:
		credDict = CredDocument()
		arrType = credDict[credType]
		return arrType.keys()
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s\n" % (credType))
		return None

def GetCredentialsTypes():
	"""Returns the various credential types taken form the confidential file: """
	try:
		credDict = CredDocument()
		return credDict.keys()
	except KeyError:
		sys.stderr.write("GetCredentials Invalid document\n")
		return None

def DumpToFile(credDict):
	filNam = CredFilNam()
	filFil = open(filNam, 'w')
	json.dump(credDict, filFil)
	filFil.close()

def AddCredential(credType,credName,credUsr,credPwd):
	credDict = CredDocument()
	try:
		credDict[credType][credName] = [credUsr,credPwd]
	except KeyError:
		try:
			credDict[credType] = { credName : [credUsr,credPwd] }
		except KeyError:
			credDict = { credType: { credName : [credUsr,credPwd] } }

	DumpToFile(credDict)

def UpdatesCredentials(credMapOut):
	credDict = dict()
	for credType in credMapOut:
		credDict[credType] = dict()
		for credName in credMapOut[credType]:
			cred = credMapOut[credType][credName]
			credDict[credType][credName] = [ cred[0], cred[1] ]
	DumpToFile(credDict)
