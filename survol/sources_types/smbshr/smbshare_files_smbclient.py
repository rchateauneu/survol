#!/usr/bin/env python

"""
SMB shares accessed with smbclient
"""

#$ smbclient -c "ls" -D "My Music"  //192.168.1.67/SharedDocs ""
#Domain=[PCVERO] OS=[Windows 5.1] Server=[Windows 2000 LAN Manager]
#  .                                  DR        0  Sat May 18 22:48:01 2013
#  ..                                 DR        0  Sat May 18 22:48:01 2013
#  Desktop.ini                       AHS      151  Wed May  1 19:46:06 2013
#  music.bmp                                18486  Mon Mar 31 13:00:20 2003
#  music.wma                           A  3492199  Mon Mar 31 13:00:00 2003
#  My Playlists                        D        0  Wed May  1 14:14:55 2013
#  Sample Music                       DR        0  Wed May  1 19:46:06 2013
#  Sample Playlists                    D        0  Wed May  1 14:38:36 2013
#
#$ smbclient -c "ls" -D "My Music/My Playlists"  //192.168.1.67/SharedDocs "" 

import re
import os
import sys

import lib_smbclient
import lib_util
import lib_common
from lib_properties import pc

Usable = lib_util.UsableLinux

def Main():
	paramkeyPassword = "Password"

	cgiEnv = lib_common.CgiEnv(
		{ paramkeyPassword : "" } )

	if lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("smbclient not available on Windows")

	smbShr = cgiEnv.GetId()
	password = cgiEnv.get_parameters( paramkeyPassword )

	nodeSmbShr = lib_common.gUriGen.SmbShareUri( smbShr )

	grph = cgiEnv.GetGraph()

	smbDir = ""

	lib_smbclient.AddFromSmbClient( grph, smbDir, smbShr, password, nodeSmbShr )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
