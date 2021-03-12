#!/usr/bin/env python

"""
Windows users
"""

import sys
import logging
import lib_util
import lib_common
from lib_properties import pc

import lib_win32
import win32net
import win32netcon

from sources_types import Win32_UserAccount as survol_Win32_UserAccount


def Main():
    cgiEnv = lib_common.CgiEnv()
    hostname = cgiEnv.GetId()

    node_host = lib_common.gUriGen.HostnameUri(hostname)

    grph = cgiEnv.GetGraph()

    try:
        lib_win32.WNetAddConnect(hostname)
    except Exception as exc:
        lib_common.ErrorMessageHtml("NetUserEnum:" + str(exc))

    # This could be a parameter. Hard-coded value for the moment.
    if lib_util.is_local_address(hostname):
        level = 2 # 1,2
    else:
        level = 2 # 1,2

    logging.debug("hostname=%s level=%d", hostname, level)

    resume_handle = 0

    while True:
        try:
            # Connects a computer to or disconnects a computer from a shared resource, or displays information about computer connections.
            # The command also controls persistent net connections. Used without parameters, net use retrieves a list of network connections.
            # net use [{DeviceName | *}] [\\ComputerName\ShareName[\volume]] [{Password | *}]] [/user:[DomainName\]UserName]
            #  [/user:[DottedDomainName\]UserName] [/user: [UserName@DottedDomainName] [/savecred] [/smartcard] [{/delete | /persistent:{yes | no}}]

            # https://mail.python.org/pipermail/python-win32/2003-April/000961.html
            lst_users, total, resume_handle = win32net.NetUserEnum(
                                                                   hostname,
                                                                   level,
                                                                   win32netcon.FILTER_NORMAL_ACCOUNT,
                                                                   resume_handle)
        except Exception as exc:
            lib_common.ErrorMessageHtml("NetUserEnum:" + str(exc))

        for usr_elt in lst_users:
            # {'comment': u'Built-in account for administering the computer/domain', 'workstations': u'', 'country_code': 0L, 'last_logon': 1426
            # 729970L, 'full_name': u'', 'parms': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', '
            # usr_comment': u'', 'acct_expires': 4294967295L, 'bad_pw_count': 0L, 'logon_hours': '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff
            # \xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L, 'last_logoff': 0L, 'name': u'Administrator', 'max_s
            # torage': 4294967295L, 'num_logons': 11L, 'password_age': 191184801L, 'flags': 66083L, 'script_path': u''},

            user_name = usr_elt['name']

            node_user = survol_Win32_UserAccount.MakeUri(user_name, hostname)
            grph.add((node_host, pc.property_user, node_user))

            try:
                txt_comment = usr_elt['comment']
                grph.add((node_user, pc.property_information, lib_util.NodeLiteral(txt_comment)))
            except KeyError:
                pass
        if resume_handle == 0:
            break

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

