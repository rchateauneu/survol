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

class Impersonate:
	def __init__(self,login,password,domain):
		# LOGON32_LOGON_NETWORK
		# win32con.LOGON32_LOGON_INTERACTIVE
		self.m_handle=win32security.LogonUser(login,domain,password,win32con.LOGON32_LOGON_NETWORK,win32con.LOGON32_PROVIDER_DEFAULT)
		win32security.ImpersonateLoggedOnUser(self.m_handle)
		sys.stderr.write("Username=%s\n" % win32api.GetUserName() )
	def __del__(self):
		win32security.RevertToSelf()
		self.m_handle.Close()

# Ca fonctionne pour OpenSCManager.
# Si on ne le fait pas: "(5, 'NetLocalGroupEnum', 'Access is denied.')"
# Si on le fait, quelque soit le password: "(127, 'NetLocalGroupEnum', 'The specified procedure could not be found.')"
def MakeImpersonate(machineName):
	sys.stderr.write("MakeImpersonate: machineName=%s\n" % machineName)
	(usernam,passwd) = lib_credentials.GetCredentials("Login",machineName)
	if usernam != '':
		imper = Impersonate(usernam,passwd, machineName)
		sys.stderr.write("MakeImpersonate: Connect %s OK\n" % machineName)
	else:
		sys.stderr.write("MakeImpersonate: No impersonate on %s. Returning None.\n" % machineName)
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
            strInfoPath = u'\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, propName)
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
