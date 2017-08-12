#!/usr/bin/python

"""
Disk partitions
"""

import sys
import socket
import psutil
import lib_util
import lib_common
from lib_properties import pc

# TODO: J ai l impresison que sous Windows, nous enumerons en fait les mount points.
# Win32_MountPoint
# C est une association entre Win32_Directory et Win32_Volume:
# http://127.0.0.1/Survol/survol/class_wmi.py?xid=\\rchateau-HP\root\CIMV2%3AWin32_MountPoint.
#
#
# MIEUX: Win32_LogicalDisk qui derive aussi de CIM_LogicalDisk, CIM_StorageExtent
# Mais ca ne marche que sous Windows.
# Sous Linux, ca sort quelque chose de different.
# Mais est-ce vraiment un probleme ?
# De oute facon ces scripts servent a sortir des donnees en vrac, ils sont la plus ou moins
# a titre indicatif. Il faut les montrer si classes de bse ou bien derivee: L important est de passer vers d autres objets.
# On peut aussi dire que nos objects derivent de LMI_MountedFileSystem ou autres, ce qui evite de trouver le match parfait.
# Notons aussi que c'est juste un ou deux scripts qui nous bloquent.
#
# C est a peu pres CIM_StorageExtent


# http://192.168.1.88/yawn/GetClass/LMI_LVStorageExtent?url=http%3A%2F%2Flocalhost&verify=0&ns=root%2Fcimv2
# Mais yapas les mount points. Ou alors certains element LMI_MountedFileSystem plus boot.
# Bref, je ne sais pas ce que c'est d un point de vue CIM.
# On peut dupliquer et lui donner deux noms ?
# Ou bien un nom generique et on ne le raccroche pas a une classe ?
# Ou bien une classe de base tres generale ? Et on ne pretend pas a l'exhaustivite. "enumerate" veut juste dire "quelques".


# On va prendre CIM_LogicalDisk


# Cote Unix, lmtab explore LMI_MountedFileSystem (qui descend de CIM_View et c est tout)
# http://192.168.1.88/yawn/EnumInstanceNames/LMI_MountedFileSystem?url=http%3A%2F%2Flocalhost&verify=0&ns=root%2Fcimv2
#string FileSystemSpec;
#Filesystem specification. Corresponds to the device field in /etc/fstab.
#string MountPointPath;
#Path to a directory where the device is mounted.



# Windows
# [sdiskpart(device='C:\\', mountpoint='C:\\', fstype='NTFS', opts='rw,fixed'),
# sdiskpart(device='D:\\', mountpoint='D:\\', fstype='NTFS', opts='rw,fixed')]
# Linux
# [partition(device='/dev/sda1', mountpoint='/', fstype='ext3', opts='rw'), partition(device='/dev/sda6', mountpoint='/home', fstype='ext3', opts='rw'), partition(device='/dev/sdb1', mountpoint='/samsung', fstype='ext2', opts='rw')]

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	for part in psutil.disk_partitions():
		# partition(device='D:\\\\', mountpoint='D:\\\\', fstype='NTFS', opts='rw,fixed')
		sys.stderr.write("device=%s fstype=%s\n" % (part.device,part.fstype) )
		sys.stderr.write("All=%s\n" % str(part) )
		# Replacing backslashes is necessary on Windows.
		partition_name = part.device.replace('\\','/')

		# BEWARE: This is not very clear.
		if lib_util.isPlatformWindows:
			# DeviceID     : X:
			# DriveType    : 4
			# ProviderName : \\192.168.1.81\rchateau
			# FreeSpace    : 170954825728
			# Size         : 2949169561600
			# VolumeName   : rchateau
			#
			# WMI does not want a backslash at the end: "C:".
			partition_name = partition_name.replace("/","")
			# We could as well take "Win32_LogicalDisk" because it inherits from "CIM_LogicalDisk"
			nodePartition = lib_common.gUriGen.UriMake("CIM_LogicalDisk",partition_name)
		else:
			# This does not really work on Windows because WMI expects
			# something like 'Win32_DiskPartition.DeviceID="Disk #0.Partition #0"'
			nodePartition = lib_common.gUriGen.DiskPartitionUri( partition_name )

		mount_point = part.mountpoint.replace('\\','/')
		nodeMount = lib_common.gUriGen.DirectoryUri( mount_point )

		# TODO: Check this list.
		if part.fstype != "":
			# partition(device='T:\\\\', mountpoint='T:\\\\', fstype='', opts='cdrom')
			grph.add( ( nodePartition, pc.property_file_system_type, lib_common.NodeLiteral(part.fstype) ) )
			grph.add( ( nodeMount, pc.property_mount, nodePartition ) )

		if part.opts != "":
			grph.add( ( nodePartition, pc.property_mount_options,  lib_common.NodeLiteral(part.opts) ) )

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()

