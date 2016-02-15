#!/usr/bin/python

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import sys
import time
import rdflib
import psutil
import lib_entities.lib_entity_file
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("File information")
filNam = cgiEnv.GetId()
sys.stderr.write("filNam=%s\n" % filNam )

filNode = lib_common.gUriGen.FileUri(filNam )

grph = rdflib.Graph()

try:
	info = os.stat(filNam)
except Exception:
	# On recent Python versions, we would catch IOError or FileNotFoundError.
	exc = sys.exc_info()[1]
	lib_common.ErrorMessageHtml("Caught:"+str(exc))
except IOError:
	lib_common.ErrorMessageHtml("IOError:"+filNam)
except FileNotFoundError:
	lib_common.ErrorMessageHtml("File not found:"+filNam)
except PermissionError:
	lib_common.ErrorMessageHtml("Permission error:"+filNam)
except OSError:
	lib_common.ErrorMessageHtml("Incorrect syntax:"+filNam)

# st_mode: protection bits.
# st_ino: inode number.

# st_dev: device.
deviceName = "Device:"+str(info.st_dev)
if "linux" in sys.platform:
	# TODO: How to get the device name on Windows ???
	for line in file('/proc/mounts'):
		# lines are device, mountpoint, filesystem, <rest>
		# later entries override earlier ones
		line = [s.decode('string_escape') for s in line.split()[:3]]
		if os.lstat(line[1]).st_dev == info.st_dev:
			deviceName = line[1]
			break

	deviceNode = lib_common.gUriGen.DiskPartitionUri(deviceName)
	grph.add( ( filNode, pc.property_file_device, deviceNode ) )

lib_entities.lib_entity_file.AddStatNode( grph, filNode, info )
lib_entities.lib_entity_file.AddMagic( grph, filNode, filNam )

# st_nlink: number of hard links.

# st_uid: user id of owner.
try:
	# Can work on Unix only.
	import pwd
	user = pwd.getpwuid( info.st_uid )
	userName = user[0]
	userNode = lib_common.gUriGen.UserUri(userName)
	grph.add( ( filNode, pc.property_owner, userNode ) )
except ImportError:
	pass

# st_gid: group id of owner.
try:
	# Can work on Unix only.
	import grp
	group = grp.getgrgid( info.st_gid )
	groupName = group[0]
	groupNode = lib_common.gUriGen.GroupUri(groupName)
	grph.add( ( filNode, pc.property_group, groupNode ) )
except ImportError:
	pass

# Displays the parent directories/
currFilNam = filNam
currNode = filNode
while True:
	dirPath = os.path.dirname( currFilNam )
	if dirPath == currFilNam:
		break
	if dirPath == "":
		break
	dirNode = lib_common.gUriGen.FileUri( dirPath )
	grph.add( ( dirNode, pc.property_directory, currNode ) )
	sys.stderr.write("dirPath=%s\n" % dirPath)
	statPath = os.stat(dirPath)
	lib_entities.lib_entity_file.AddStatNode( grph, dirNode, statPath )
	currFilNam = dirPath
	currNode = dirNode

# cgiEnv.OutCgiRdf(grph)
cgiEnv.OutCgiRdf(grph,"LAYOUT_TWOPI")

