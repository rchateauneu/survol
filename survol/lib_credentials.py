import os
import sys
import json
import lib_util

# TODO: Several accesses per machine or database ?
# TODO: What if an access for "192.168.1.78" and "titi" ?


def credentials_filename():
	"""This returns the file name containing the credentials.
	The filename can be overloaded with an environment variable."""
	credentials_basname = "SurvolCredentials.json"

	if lib_util.isPlatformLinux:
		home_directory = os.environ["HOME"]
	else:
		try:
			home_drive = os.environ["HOMEDRIVE"]
		except:
			home_drive = "C:"
		home_directory = os.path.join(home_drive, os.environ["HOMEPATH"])
	cred_name = os.path.join(home_directory, credentials_basname).strip()

	if os.path.isfile(cred_name):
		return cred_name

	cred_name = os.path.join(lib_util.gblTopScripts, "..", credentials_basname).strip()
	if os.path.isfile(cred_name):
		return cred_name

	raise Exception("Cannot find a credentials filename:%s" % cred_name)


def _build_credentials_document():
	"""This returns a map containing all credentials."""

	file_name = credentials_filename()

	try:
		with open(file_name) as cred_file:
			json_creds = json.load(cred_file)

		return json_creds
	except Exception as exc:
		WARNING("_build_credentials_document no credentials %s: %s", file_name, str(exc))
		return dict()


def _credentials_document():
	if not _credentials_document.credentials:
		_credentials_document.credentials = _build_credentials_document()

	return _credentials_document.credentials


_credentials_document.credentials = None


# For example: GetCredentials("Oracle","XE") or GetCredentials("Login","192.168.1.78")
# It returns the username and the password.
def GetCredentials( credType, credName ):
	if credName is None:
		credName = ""
	credentials = _credentials_document()
	DEBUG("GetCredentials credType=%s credName=%s credentials=%d elements",credType,credName,len(credentials))
	try:
		if not credentials:
			return ('','')
		arrType = credentials[credType]
	except KeyError:
		WARNING("GetCredentials Invalid type credType=%s credName=%s",credType,credName)
		return None

	# Try first without converting.
	try:
		cred = arrType[credName]
		# sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
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
		# sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
		return cred
	except KeyError:
		WARNING("GetCredentials Unknown name credType=%s credName=%s",credType,credName)
		return ('','')


# For example, if "credType" == "Oracle", it will returned all databases defined in the credentials file.
# TODO: For Oracle, consider exploring tnsnames.ora ?
def get_credentials_names( credType ):
	try:
		credDict = _credentials_document()
		arrType = credDict[credType]
		return arrType.keys()
	except KeyError:
		ERROR("GetCredentials Invalid type credType=%s",credType)
		return []


def get_credentials_types():
	"""Returns the various credential types taken form the confidential file: """
	try:
		credDict = _credentials_document()
		return credDict.keys()
	except KeyError:
		ERROR("GetCredentials Invalid document")
		return None


def _dump_credentials_to_file(credDict):
	filNam = credentials_filename()
	filFil = open(filNam, 'w')
	json.dump(credDict, filFil)
	filFil.close()


def add_one_credential(credType, credName, credUsr, credPwd):
	credDict = _credentials_document()
	try:
		credDict[credType][credName] = [credUsr, credPwd]
	except KeyError:
		try:
			credDict[credType] = {credName : [credUsr,credPwd]}
		except KeyError:
			credDict = {credType: {credName : [credUsr,credPwd]}}

	_dump_credentials_to_file(credDict)


def update_credentials(credMapOut):
	credDict = dict()
	for credType in credMapOut:
		credDict[credType] = dict()
		for credName in credMapOut[credType]:
			cred = credMapOut[credType][credName]
			credDict[credType][credName] = [ cred[0], cred[1] ]
	_dump_credentials_to_file(credDict)


def key_url_cgi_encode(aKeyUrl):
	return aKeyUrl.replace("http://","http:%2F%2F").replace("https://","https:%2F%2F")
