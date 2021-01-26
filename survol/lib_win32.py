import os
import sys
import logging
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
    def __init__(self, login, password, domain):
        # LOGON32_LOGON_NETWORK
        # win32con.LOGON32_LOGON_INTERACTIVE
        logging.debug("Impersonate login=%s domain=%s", login, domain)
        self.m_handle=win32security.LogonUser(
            login, domain, password, win32con.LOGON32_LOGON_NETWORK, win32con.LOGON32_PROVIDER_DEFAULT)
        logging.debug("After win32security.LogonUser handle=%s ", str(self.m_handle))
        try:
            win32security.ImpersonateLoggedOnUser(self.m_handle)
        except Exception as exc:
            logging.warning("win32security.ImpersonateLoggedOnUser: handle=%s Caught %s", str(self.m_handle), exc)

        logging.debug("Username=%s", win32api.GetUserName())

    def __del__(self):
        win32security.RevertToSelf()
        self.m_handle.Close()


# TODO: It does not work with OpenSCManager.
# TODO: If this is not done: "(5, 'NetLocalGroupEnum', 'Access is denied.')"
# TODO: If this is done, whatever the password: "(127, 'NetLocalGroupEnum', 'The specified procedure could not be found.')"
# TODO: BEWARE: Apparently it does not work for remote machines before NetShareEnum. When using it,
# TODO: with another machine etc... we obtain GetUserName() = "Guest" and of course access denied everywjhere.
def MakeImpersonate(machine_name):
    if not machine_name:
        return None, None

    current_user_name = win32api.GetUserName()
    logging.debug("MakeImpersonate: machineName=%s current_user_name=%s", machine_name, current_user_name)

    # "machinename" or "Machinename" ? Arp returns "Machinename".
    usernam, passwd = lib_credentials.GetCredentials("Login", machine_name)
    logging.debug("MakeImpersonate: usernam=%s", usernam )

    if usernam != '':
        if usernam == current_user_name:
            logging.debug("MakeImpersonate: Already %s", current_user_name)
            imper = None
        else:
            try:
                imper = Impersonate(usernam, passwd, machine_name)
            except Exception as exc:
                logging.warning("MakeImpersonate: Caught %s", exc)
                imper = None
    else:
        logging.debug("MakeImpersonate: No impersonate on %s. Returning None.", machine_name)
        imper = None

    # If running on the local machine, pass the host as None otherwise authorization is checked
    # just like a remote machine, which means User Account Control (UAC) disabling,
    # and maybe setting LocalAccountTokenFilterPolicy=1
    if machine_name == lib_util.currentHostname:
        mach_name_or_none = None
    else:
        mach_name_or_none = machine_name

    return mach_name_or_none, imper


def CheckWindowsModule(win_module):
    if not lib_util.isPlatformWindows:
        lib_common.ErrorMessageHtml("DLL files are on Windows platforms only")

    if os.path.isdir(win_module):
        lib_common.ErrorMessageHtml("File '" + win_module + "' must be a plain file")

    if not os.path.isfile(win_module):
        lib_common.ErrorMessageHtml("File '" + win_module + "' does not exist")

    filename, file_extension = os.path.splitext(win_module)
    if not file_extension.upper() in ('.EXE', '.DLL'):
        lib_common.ErrorMessageHtml(
            "File '" + win_module + "' should be a Windows module. Extension=" + file_extension)


# http://stackoverflow.com/questions/580924/python-windows-file-version-attribute
def getFileProperties(fname):
    """
    Read all properties of the given file return them as a dictionary.
    """
    prop_names = (
        'Comments', 'InternalName', 'ProductName',
        'CompanyName', 'LegalCopyright', 'ProductVersion',
        'FileDescription', 'LegalTrademarks', 'PrivateBuild',
        'FileVersion', 'OriginalFilename', 'SpecialBuild')

    props = {'FixedFileInfo': None, 'StringFileInfo': None, 'FileVersion': None}

    try:
        # backslash as parm returns dictionary of numeric info corresponding to VS_FIXEDFILEINFO struc
        fixed_info = win32api.GetFileVersionInfo(fname, '\\')
        props['FixedFileInfo'] = fixed_info
        props['FileVersion'] = "%d.%d.%d.%d" % (fixed_info['FileVersionMS'] / 65536,
                fixed_info['FileVersionMS'] % 65536, fixed_info['FileVersionLS'] / 65536,
                fixed_info['FileVersionLS'] % 65536)

        # \VarFileInfo\Translation returns list of available (language, codepage)
        # pairs that can be used to retreive string info. We are using only the first pair.
        lang, codepage = win32api.GetFileVersionInfo(fname, '\\VarFileInfo\\Translation')[0]

        # any other must be of the form \StringfileInfo\%04X%04X\parm_name, middle
        # two are language/codepage pair returned from above

        str_info = {}
        for prop_name in prop_names:
            str_info_path = '\\StringFileInfo\\%04X%04X\\%s' % (lang, codepage, prop_name)
            str_info[prop_name] = win32api.GetFileVersionInfo(fname, str_info_path)

        props['StringFileInfo'] = str_info
    except:
        pass

    return props


def WindowsCompletePath():
    """Try paths as described in MSDN"""
    path = win32api.GetEnvironmentVariable('PATH')
    dirs = [os.getcwd(), win32api.GetSystemDirectory(), win32api.GetWindowsDirectory()] + path.split(';')

    dirs_norm = []
    dirs_l = []
    for a_dir in dirs:
        a_dir_lower = a_dir.lower()
        if a_dir_lower not in dirs_l:
            dirs_l.append(a_dir_lower)
            dirs_norm.append(a_dir)

    return dirs_norm


def WNetAddConnect(machine_name_no_backslash):
    # Nothing to do if this is the current machine.
    if not machine_name_no_backslash:
        return
    # "machine" or "Machine" ? Arp returns "Machine".
    usernam, passwd = lib_credentials.GetCredentials("Login", machine_name_no_backslash)

    mach_nam_with_backslash = "\\\\" + machine_name_no_backslash

    win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_ANY, None,
                                 mach_nam_with_backslash, None, usernam, passwd, 0)


def VersionString(fil_nam):
    try:
        info = win32api.GetFileVersionInfo(fil_nam, "\\")
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        return "%d.%d.%d.%d" % (win32api.HIWORD(ms), win32api.LOWORD(ms), win32api.HIWORD(ls), win32api.LOWORD(ls))
    except:
        return None

