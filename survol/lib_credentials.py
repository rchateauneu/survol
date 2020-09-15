import os
import sys
import json
import lib_util

# TODO: Several accesses per machine or database ?
# TODO: What if an access for "192.168.1.78" and "titi" ?

# This returns the file name containing the credentials.
def credentials_filename():
	filNamOnly = "SurvolCredentials.json"
	try:
		return os.environ["HOME"] + "/" + filNamOnly
	except KeyError:
		DEBUG("HOME not defined")
		pass

	try:
		return os.environ["HOMEPATH"] + "\\" + filNamOnly
	except KeyError:
		DEBUG("HOMEPATH not defined")
		pass

	dirNam = lib_util.gblTopScripts

	filNam = dirNam + "/../../" + filNamOnly

	return filNam

def _build_credentials_document():
	"""This returns a map containing all credentials."""

	# /home/travis/build/rchateauneu/survol : See "tests/init.py" for the same test.
	# So the passwords are encrypted in environment variables:
	# https://stackoverflow.com/questions/9338428/using-secret-api-keys-on-travis-ci/12778315#12778315
	if os.getcwd().find("travis") >= 0:
		# When testing on Travis CI, the credentials are encoded in an environment variable set in the Web interface.
		WARNING("_build_credentials_document Travis mode")

		# Actual value: of the environment variable SURVOL_CREDENTIALS
		# Some characters must be escaled: Double-quotes, colons, curly and square brackets, maybe more.
		# travis_credentials_env = \{\"WBEM\":\{\"http://vps516494.ovh.net:5988\"\:\[\"xxx\",\"yyy\"\]\}\}
		# travis_credentials_env = \{\"WBEM\":\{\"http://vps516494.ovh.net:5988\"\:\[\"xxx\",\"yyy\"\]\},\"Storage\"\:\{\"Events\"\:\[\"SQLAlchemy\", \"sqlite:///C:/tmp/survol_events.sqlite?mode=memory&cache=shared\"\]\}\}
		travis_credentials_env = os.environ["SURVOL_CREDENTIALS"]
		DEBUG("_build_credentials_document travis_credentials=%s", travis_credentials_env)
		travis_credentials = json.loads(travis_credentials_env)
		return travis_credentials

	filNam = credentials_filename()
	try:
		opFil = open(filNam)
		jsonCreds = json.load( opFil )
		opFil.close()

		upperCredentials = dict()
		for keyCred in jsonCreds:
			keyVal = jsonCreds[keyCred]
			upperCredentials[keyCred] = keyVal

		return upperCredentials
	except Exception:
		WARNING("_build_credentials_document no credentials %s: %s", filNam, str(sys.exc_info()))
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
def GetCredentialsNames( credType ):
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
