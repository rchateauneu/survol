#!/usr/bin/python

import socket
import rdflib
import lib_common
from lib_common import pc

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

bad_types = [ 'proc', 'binfmt_misc', 'fusectl' ]

for mnt_line in open("/etc/mtab","r"):
	mnt_split = mnt_line.split(' ')
	if ( mnt_split[2] in bad_types ):
		continue
	partition_name = mnt_split[0]
	mnt_point = mnt_split[1]

	grph.add( ( lib_common.FileUri( mnt_point ), pc.property_mount, lib_common.DiskPartitionUri( partition_name ) ) )

lib_common.OutCgiRdf(grph)

