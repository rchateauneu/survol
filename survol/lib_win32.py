import os
import sys
import lib_util
import lib_common
import lib_credentials

import win32api
import win32net
import win32con
import win32netcon
import win32security
import win32wnet # WNetAddConnection2

class Impersonate:
	def __init__(self,login,password,domain):
		# LOGON32_LOGON_NETWORK
		# win32con.LOGON32_LOGON_INTERACTIVE
		DEBUG("Impersonate login=%s domain=%s", login, domain)
		self.m_handle=win32security.LogonUser(login,domain,password,win32con.LOGON32_LOGON_NETWORK,win32con.LOGON32_PROVIDER_DEFAULT)
		DEBUG("After win32security.LogonUser handle=%s ", str(self.m_handle))
		try:
			win32security.ImpersonateLoggedOnUser(self.m_handle)
		except Exception:
			WARNING("win32security.ImpersonateLoggedOnUser: handle=%s Caught %s", str(self.m_handle),str(sys.exc_info()))

		DEBUG("Username=%s", win32api.GetUserName() )
	def __del__(self):
		win32security.RevertToSelf()
		self.m_handle.Close()

# TODO: It does not work OpenSCManager.
# TODO: If this is not done: "(5, 'NetLocalGroupEnum', 'Access is denied.')"
# TODO: If this is done, whatever the password: "(127, 'NetLocalGroupEnum', 'The specified procedure could not be found.')"
# TODO: BEWARE: Apparently it does not work for remote machines before NetShareEnum. When using it,
# TODO: with another machine etc... we obtain GetUserName() = "Guest" and of course access denied everywjhere.
def MakeImpersonate(machineName):
	if not machineName:
		return None, None

	currentUserName =  win32api.GetUserName()
	DEBUG("MakeImpersonate: machineName=%s currentUserName=%s", machineName,  currentUserName )

	# "titi" ou "Titi" ? Arp returns "Titi".
	(usernam,passwd) = lib_credentials.GetCredentials("Login",machineName)
	DEBUG("MakeImpersonate: usernam=%s", usernam )

	if usernam != '':
		if usernam == currentUserName:
			DEBUG("MakeImpersonate: Already %s", currentUserName)
			imper = None
		else:
			try:
				imper = Impersonate(usernam,passwd, machineName)
			except Exception:
				WARNING("MakeImpersonate: Caught %s", str(sys.exc_info()))
				imper = None
	else:
		DEBUG("MakeImpersonate: No impersonate on %s. Returning None.", machineName)
		imper = None

	# If running on the local machine, pass the host as None otherwise authorization is checked
	# just like a remote machine, which means User Account Control (UAC) disabling,
	# and maybe setting LocalAccountTokenFilterPolicy=1
	if machineName == lib_util.currentHostname:
		machName_or_None = None
	else:
		machName_or_None = machineName

	return machName_or_None, imper

def CheckWindowsModule(win_module):
	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("DLL files are on Windows platforms only")

	if os.path.isdir(win_module):
		lib_common.ErrorMessageHtml("File '" + win_module + "' must be a plain file")

	if not os.path.isfile(win_module):
		lib_common.ErrorMessageHtml("File '" + win_module + "' does not exist")

	filename, file_extension = os.path.splitext(win_module)
	if not file_extension.upper() in ( '.EXE','.DLL' ):
		lib_common.ErrorMessageHtml("File '" + win_module + "' should be a Windows module. Extension="+file_extension)

# http://stackoverflow.com/questions/580924/python-windows-file-version-attribute
def getFileProperties(fname):
    """
    Read all properties of the given file return them as a dictionary.
    """
    propNames = ('Comments', 'InternalName', 'ProductName',
        'CompanyName', 'LegalCopyright', 'ProductVersion',
        'FileDescription', 'LegalTrademarks', 'PrivateBuild',
        'FileVersion', 'OriginalFilename', 'SpecialBuild')

    props = {'FixedFileInfo': None, 'StringFileInfo': None, 'FileVersion': None}

    try:
        # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc
        fixedInfo = win32api.GetFileVersionInfo(fname, '\\')
        props['FixedFileInfo'] = fixedInfo
        props['FileVersion'] = "%d.%d.%d.%d" % (fixedInfo['FileVersionMS'] / 65536,
                fixedInfo['FileVersionMS'] % 65536, fixedInfo['FileVersionLS'] / 65536,
                fixedInfo['FileVersionLS'] % 65536)

        # \VarFileInfo\Translation returns list of available (language, codepage)
        # pairs that can be used to retreive string info. We are using only the first pair.
        lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]

        # any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle
        # two are language/codepage pair returned from above

        strInfo = {}
        for propName in propNames:
            strInfoPath = '\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
            ## print str_info
            strInfo[propName] = win32api.GetFileVersionInfo(fname, strInfoPath)

        props['StringFileInfo'] = strInfo
    except:
        pass

    return props


# try paths as described in MSDN
def WindowsCompletePath():
	path = win32api.GetEnvironmentVariable('PATH')
	dirs = [os.getcwd(), win32api.GetSystemDirectory(), win32api.GetWindowsDirectory()] + path.split(';')

	dirs_norm = []
	dirs_l = []
	for aDir in dirs:
		aDirLower = aDir.lower()
		if aDirLower not in dirs_l:
			dirs_l.append(aDirLower)
			dirs_norm.append(aDir)

	return dirs_norm

def WNetAddConnect(machineNameNoBackslash):
	# Nothing to do if this is the current machine.
	if not machineNameNoBackslash:
		return
	# "titi" ou "Titi" ? Arp retourne "Titi".
	(usernam,passwd) = lib_credentials.GetCredentials("Login",machineNameNoBackslash)

	# 	"Titi":["titi\\rchateauneu@hotmail.com", "trxxxxxxa"],

	machNamWithBackslash = "\\\\" + machineNameNoBackslash

	## CA MARCHE !!!!!!!!
	win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_ANY, None,machNamWithBackslash, None, usernam,passwd, 0)

def VersionString (filNam):
    try:
        info = win32api.GetFileVersionInfo (filNam, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return "%d.%d.%d.%d" % ( win32api.HIWORD (ms), win32api.LOWORD (ms), win32api.HIWORD (ls), win32api.LOWORD (ls) )
    except:
        return None

