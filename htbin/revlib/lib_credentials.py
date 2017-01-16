import os
import sys
import json
import lib_util

# TODO: Several accesses per machine or database ?
# TODO: What if an access for "192.168.1.78" and "titi" ?


def BuildCredDocument():
	def CredFilNam():
		dirNam = lib_util.gblTopScripts

		filNam = dirNam + "/../../SurvolCredentials.json"

		return filNam

	filNam = CredFilNam()
	try:
		jsonCreds = json.load( open(filNam) )
		# return jsonCreds
		# sys.stderr.write("CredDocument credentials=%d elements\n" % (len(credentials)))

		# Now converts the internal keys to uppercase. This because machines name are unperdictaly converted
		# to lower or upper case, or capitalised.
		upperCredentials = dict()
		for keyCred in jsonCreds:
			keyVal = jsonCreds[keyCred]
			keyValUp = { subKey.upper() : keyVal[subKey] for subKey in keyVal }
			upperCredentials[keyCred] = keyValUp

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
	credentials = CredDocument()
	sys.stderr.write("GetCredentials credType=%s credName=%s credentials=%d elements\n" % (credType,credName,len(credentials)))
	try:
		if not credentials:
			return ('','')
		arrType = credentials[credType]
		try:
			# We must convert the machine names to uppercase because this is "sometimes" done by Windows.
			# Might be a problem for database names.
			if credName:
				credName = credName.upper()
			cred = arrType[credName]
			sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
			return cred
		except KeyError:
			sys.stderr.write("GetCredentials Unknown name credType=%s credName=%s\n" % (credType,credName))
			return ('','')
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s credName=%s\n" % (credType,credName))
		return None

# For example, if "credType" == "Oracle", it will returned all databases defined in the credentials file.
# TODO: For Oracle, consider exploring tnsnames.ora ?
def GetCredentialsNames( credType ):
	try:
		credentials = CredDocument()
		arrType = credentials[credType]
		return arrType.keys()
	except KeyError:
		sys.stderr.write("GetCredentials Invalid type credType=%s\n" % (credType))
		return None

