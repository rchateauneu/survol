import os
import sys
import lib_util
import lib_common
import lib_credentials

try:
	import win32api
	import win32net
	import win32con
	import win32netcon
	import win32security
except ImportError:
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("win32 Python library not installed:"+str(exc))

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


