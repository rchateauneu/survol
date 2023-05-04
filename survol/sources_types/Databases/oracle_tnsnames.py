#!/usr/bin/env python

"""
TNSNAMES file
"""

import os
import sys
import re
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

from sources_types.oracle import db as oracle_db

###########################################################################################    
    
def parse_one(grph, database_dicts, database):
    # Get the database name and a set of (name, value) pairs.
    try:
        name = re.match(r'(\w+)', database).group(1)
    except AttributeError:
        # AttributeError: 'NoneType' object has no attribute 'group'
        return

    names_and_values = re.findall(r'(?i)([a-z]+)\s*=\s*([a-z0-9-\.]+)', database)
        
    # Build a dictionary from them, and if it has a HOST, add the IP.
    database_dict = dict(names_and_values)

    try:
        node_addr = lib_uris.gUriGen.AddrUri(database_dict['HOST'], database_dict['PORT'])
    except KeyError:
        return
    
    # Here we should do something better, for example getting more information about this database.
    node_oradb = oracle_db.MakeUri(name)

    grph.add((node_addr, pc.property_oracle_db, node_oradb))

    
def parse_all(grph, text):
    database_dicts = {}

    # Strip comments and blank lines.
    text = re.sub(r'#[^\n]*\n', '\n', text)
    text = re.sub(r'( *\n *)+', '\n', text.strip())
    
    # Split into database entries by balancing the parentheses.
    databases = []
    start = 0
    c = 0
    len_text = len(text)
    while c < len_text:
        parens = 0
        c = text.find('(',start)
        
        while c < len_text:
            text_c = text[c]
            c += 1
            if text_c == '(':
                parens += 1
            elif text_c == ')':
                parens -= 1
                if parens == 0:
                    break
        
        parse_one( grph, database_dicts, text[start:c].strip() )

        start = c
    
    return database_dicts

###########################################################################################    

# http://www.dba-oracle.com/t_windows_tnsnames.ora_file_location.htm
# According to the docs, the precedence in which Oracle Net
# Configuration files are resolved is:
# Oracle Net files in present working directory (PWD/CWD)
# TNS_ADMIN set for each session session or by a user-defined script
# TNS_ADMIN set as a global environment variable
# TNS_ADMIN as defined in the registry
# Oracle Net files in %ORACLE_HOME/network/admin
#(Oracle default location)
# HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\ORACLE\HOME3
# Name=TNS_ADMIN = F:\Orac\Config
#
# Key=HKEY_LOCAL_MACHINE\SOFTWARE\Oracle\KEY_XE
# Name=ORACLE_HOME
# Data=C:\oraclexe\app\oracle\product\11.2.0\server
# "C:\oraclexe\app\oracle\product\11.2.0\server\network\ADMIN\tnsnames.ora"

def GetTnsNamesWindows():
    try:
        import winreg
    except ImportError:
        logging.warning("winreg not available. Trying _winreg")
        try:
            import _winreg as winreg
        except ImportError:
            lib_common.ErrorMessageHtml("No winreg, cannot get tnsnames.ora location")

    # Tested with package _winreg.
    aReg = winreg.ConnectRegistry(None,winreg.HKEY_LOCAL_MACHINE)
    try:
        aKey = winreg.OpenKey(aReg, r"SOFTWARE\Oracle\KEY_XE")
        # except WindowsError:
    except Exception: # Probably WindowsError but we must be portable.
        # The system cannot find the file specified
        try:
            # http://stackoverflow.com/questions/9348951/python-winreg-woes
            # KEY_WOW64_64KEY 64-bit application on the 64-bit registry view.
            # KEY_WOW64_32KEY 64-bit application on the 32-bit registry view.
            # Default is ( *,*, 0, winreg.KEY_READ )
            aKey = winreg.OpenKey(aReg, r"SOFTWARE\ORACLE\KEY_HOME4",0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except Exception as exc: # Probably WindowsError but we must be portable.
            lib_common.ErrorMessageHtml("Caught %s" % str(exc))

    oraHome = None
    for i in range(1024):
        try:
            regVal=winreg.QueryValueEx(aKey, "ORACLE_HOME")
            oraHome=regVal[0]
            logging.debug("FindTnsNamesWindows oraHome=%s", str(oraHome) )
            break
        except EnvironmentError:
            break
    winreg.CloseKey(aKey)
    winreg.CloseKey(aReg)

    if oraHome is None:
        lib_common.ErrorMessageHtml("No ORACLE_HOME in registry, cannot get tnsnames.ora location")

    tnsnam = oraHome + "\\network\\ADMIN\\tnsnames.ora"
    return tnsnam

# Preferably used on Linux but can also work on Windows.
def GetTnsNamesEnvVar():
    #  If $TNS_ADMIN is not set, then the tnsnames.ora should be in $ORACLE_HOME/network/admin/.
    # $ORACLE_HOME//network/admin/tnsnames.ora
    envTNS_ADMIN = os.getenv("TNS_ADMIN")
    if envTNS_ADMIN:
        tnsnam = envTNS_ADMIN + "/tnsnames.ora"
    else:
        envORACLE_HOME = os.getenv("ORACLE_HOME")
        if envORACLE_HOME:
            tnsnam = envORACLE_HOME + "/network/admin/tnsnames.ora"
        else:
            lib_common.ErrorMessageHtml("No ORACLE_HOME nor TNS_ADMIN environment variables, cannot get tnsnames.ora location")
    return tnsnam


def GetTnsNames():

    if lib_util.isPlatformWindows:
        return GetTnsNamesWindows()

    elif lib_util.isPlatformLinux:
        return GetTnsNamesEnvVar()

    else:
        lib_common.ErrorMessageHtml("No tnsnames.ora")

    return tnsnam


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    tnsnam = GetTnsNames()

    ###########################################################################################

    try:
        # This does not work.
        # tnsnam = r"F:\Orac\Config\tnsnames.ora"
        # tnsnam=F:\Orac\Config\tnsnames.ora err=[Errno 2]
        # No such file or directory: 'F:\\Orac\\Config\\tnsnames.ora'
        # Beware that Apache might have no access right to it: 'F:\\Orac\\Config\\tnsnames.ora'
        logging.debug("tnsnam=%s", tnsnam)
        myfile = open(tnsnam, "r")
    except Exception as exc:
        lib_common.ErrorMessageHtml("tnsnam=" + tnsnam + " err=" + str(exc))

    parse_all(grph, myfile.read())
    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
