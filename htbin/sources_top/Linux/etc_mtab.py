#!/usr/bin/python

import sys
import socket
import rdflib
import lib_common
from lib_properties import pc

def Main():
	cgiEnv = lib_common.CgiEnv("Mounted disks")

	grph = rdflib.Graph()

	# $ cat /etc/mtab
	# /dev/sda1 / ext3 rw 0 0
	# none /proc proc rw 0 0
	# /dev/sda6 /home ext3 rw 0 0
	# /dev/sdb1 /samsung ext2 rw 0 0
	# none /proc/sys/fs/binfmt_misc binfmt_misc rw 0 0
	# none /sys/fs/fuse/connections fusectl rw 0 0

	# The directories will point to the disks.
	# Maybe highlight that some mount points
	# are subdirectories of others.

	try:
		# This is for Unix only.
		etc_mtab = open("/etc/mtab","r")
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Caught:" + str(exc) )

	bad_types = [ 'proc', 'binfmt_misc', 'fusectl' ]

	for mnt_line in etc_mtab:
		mnt_split = mnt_line.split(' ')
		if ( mnt_split[2] in bad_types ):
			continue
		partition_name = mnt_split[0]
		mnt_point = mnt_split[1]

		mnt_type = mnt_split[2]
		if mnt_type == 'cifs':
			nodeMount = lib_common.gUriGen.SmbShareUri( partition_name )
		else:
			nodeMount = lib_common.gUriGen.DiskPartitionUri( partition_name )
		grph.add( ( nodeMount, pc.property_mount, lib_common.gUriGen.FileUri( mnt_point ) ) )
		grph.add( ( nodeMount, pc.property_file_system, rdflib.Literal(mnt_type) ) )

	cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()
