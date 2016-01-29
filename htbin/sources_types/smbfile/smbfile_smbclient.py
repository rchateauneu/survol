#!/usr/bin/python

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

import rdflib

import lib_smbclient
import lib_common
from lib_properties import pc

paramkeyPassword = "Password"

cgiEnv = lib_common.CgiEnv(
	"Files on a SMB share, accessed with smbclient",
	"",
	{ paramkeyPassword : "" } )

if 'win' in sys.platform:
	lib_common.ErrorMessageHtml("smbclient not available on Windows")

# Top directory, not just the share name.
smbFile= cgiEnv.GetId()

# The SMB file has the form //Device/ShareName/dir1/dir2/dir3/file.

shr_mtch = re.match( "//([^/]+)/([^/]+)/(.*)", smbFile )

if not shr_mtch:
	lib_common.ErrorMessageHtml("This is not a shared file:"+smbFile)

smbShr = "//" + shr_mtch.group(1) + "/" + shr_mtch.group(2)

smbDir = shr_mtch.group(3)

password = cgiEnv.GetParameters( paramkeyPassword )

# Needed if this is the top directory.
if smbDir == "" or smbDir == "/" :
	rootNodeSmb = lib_common.gUriGen.SmbShareUri( smbShr )
else:
	# Otherwise it is the directory of the current file.
	rootNodeSmb = lib_common.gUriGen.SmbFileUri( smbShr, smbDir )

grph = rdflib.Graph()

lib_smbclient.AddFromSmbClient( grph, smbDir, smbShr, password, rootNodeSmb )

cgiEnv.OutCgiRdf(grph)
