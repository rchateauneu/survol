#!/usr/bin/env python

"""
Windows user information
"""

# >>> win32net.NetUserGetInfo(None,"jsmith",3)
# {'comment': u'', 'workstations': u'', 'country_code': 0L, 'last_logon': 1480721751L, 'password_expired': 0L, 'full_name': u'', 'parm
# s': u'', 'code_page': 0L, 'priv': 2L, 'auth_flags': 0L, 'logon_server': u'\\\\*', 'home_dir': u'', 'home_dir_drive': u'', 'usr_comme
# nt': u'', 'profile': u'', 'acct_expires': 4294967295L, 'primary_group_id': 513L, 'bad_pw_count': 0L, 'user_id': 1001L, 'logon_hours'
# : '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff', 'password': None, 'units_per_week': 168L,
# 'last_logoff': 0L, 'name': u'jsmith', 'max_storage': 4294967295L, 'num_logons': 15896L, 'password_age': 45314825L, 'flags': 66081L
# , 'script_path': u''}

import sys
import lib_util
import lib_common
from lib_properties import pc

import win32net

from sources_types import Win32_UserAccount as survol_Win32_UserAccount

Usable = lib_util.UsableWindows

CanProcessRemote = True


def Main():
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)

    try:
        # Exception if local machine.
        host_name = cgiEnv.m_entity_id_dict["Domain"]
    except KeyError:
        host_name = None

    if lib_util.is_local_address(host_name):
        serv_name_or_none = None
    else:
        serv_name_or_none = host_name

    user_name = cgiEnv.m_entity_id_dict["Name"]

    grph = cgiEnv.GetGraph()

    node_user = survol_Win32_UserAccount.MakeUri(user_name, host_name)

    try:
        info_list = win32net.NetUserGetInfo(serv_name_or_none, user_name, 2)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:" + str(exc))

    for info_key in info_list:
        try:
            info_val = info_list[info_key]
            grph.add((node_user, lib_common.MakeProp(info_key), lib_util.NodeLiteral(info_val)))
        except Exception as exc:
            txt_disp = str(exc)
            grph.add((node_user, lib_common.MakeProp(info_key), lib_util.NodeLiteral(txt_disp)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


