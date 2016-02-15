#!/usr/bin/python

"""
Disk partitions
"""

import sys
import socket
import rdflib
import psutil
import lib_util
import lib_common
from lib_properties import pc

cgiEnv = lib_common.CgiEnv("Partitions")

grph = rdflib.Graph()

# Windows
# [sdiskpart(device='C:\\', mountpoint='C:\\', fstype='NTFS', opts='rw,fixed'),
# sdiskpart(device='D:\\', mountpoint='D:\\', fstype='NTFS', opts='rw,fixed')]
# Linux
# [partition(device='/dev/sda1', mountpoint='/', fstype='ext3', opts='rw'), partition(device='/dev/sda6', mountpoint='/home', fstype='ext3', opts='rw'), partition(device='/dev/sdb1', mountpoint='/samsung', fstype='ext2', opts='rw')]

for part in psutil.disk_partitions():
	# partition(device='D:\\\\', mountpoint='D:\\\\', fstype='NTFS', opts='rw,fixed')
	sys.stderr.write("device=%s fstype=%s\n" % (part.device,part.fstype) )
	sys.stderr.write("All=%s\n" % str(part) )
	partition_name = part.device.replace('\\','/')

	# TODO: Check this list.
	if part.fstype in [ 'NTFS', 'ext2', 'ext3', 'FAT32' ]:
		nodeMount = lib_common.gUriGen.DiskPartitionUri( partition_name )
		grph.add( ( lib_common.gUriGen.FileUri( part.mountpoint ), pc.property_mount, nodeMount ) )
	elif part.fstype == "":
		nodeMount = lib_common.gUriGen.FileUri( partition_name )
	else:
		# partition(device='T:\\\\', mountpoint='T:\\\\', fstype='', opts='cdrom')
		nodeMount = lib_common.gUriGen.SmbShareUri( partition_name )
		grph.add( ( lib_common.gUriGen.FileUri( part.mountpoint ), pc.property_mount, nodeMount ) )


	if part.opts != "":
		grph.add( ( nodeMount, pc.property_mount_options,  rdflib.Literal(part.opts) ) )

	if part.fstype != "":
		grph.add( ( nodeMount, pc.property_file_system_type, rdflib.Literal(part.fstype) ) )


	# Prendre en compte le disque, l'utiliser pour iostat.
	if lib_util.isPlatformLinux:
		pass

cgiEnv.OutCgiRdf(grph)

