#!/usr/bin/env python

"""
Disk partitions

CIM_LogicalDisk objects.
"""

import sys
import socket
import logging
import psutil

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

# TODO: On Windows, it seems only to enumerate mount points.
# Win32_MountPoint
# This is an association between Win32_Directory and Win32_Volume:
# http://127.0.0.1/Survol/survol/class_wmi.py?xid=\\rchateau-HP\root\CIMV2%3AWin32_MountPoint.
#
#
# BETTER: Win32_LogicalDisk also derives from CIM_LogicalDisk, CIM_StorageExtent
# But it works only on Windows,
# On Linux this returns something different. Is it really a problem ?
# Anyway, these scripts return something approximate data.
# Maybe, just consider that they derive from LMI_MountedFileSystem or soemthign lese,
# so no need to have a perfect match.
#
# http://192.168.1.88/yawn/GetClass/LMI_LVStorageExtent?url=http%3A%2F%2Flocalhost&verify=0&ns=root%2Fcimv2
# But it does not have mount points,
#
# Should use CIM_LogicalDisk or CIM_StorageExtent.
#
# On Linux, lmtab explores LMI_MountedFileSystem (which only derives from CIM_View)
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
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    for part in psutil.disk_partitions():
        # partition(device='D:\\\\', mountpoint='D:\\\\', fstype='NTFS', opts='rw,fixed')
        logging.debug("device=%s fstype=%s", part.device,part.fstype)
        logging.debug("All=%s", str(part) )

        # BEWARE: This is not very clear.
        if lib_util.isPlatformWindows:
            # sdiskpart(device='C:\\', mountpoint='C:\\', fstype='NTFS', opts='rw,fixed')
            # DeviceID     : X:
            # DriveType    : 4
            # ProviderName : \\192.168.1.81\rchateau
            # FreeSpace    : 170954825728
            # Size         : 2949169561600
            # VolumeName   : rchateau
            #
            # WMI does not want a backslash at the end: "C:".
            # Replacing backslashes is necessary on Windows.
            partition_name = part.device.replace('\\', '')

            # We could as well take "Win32_LogicalDisk" because it inherits from "CIM_LogicalDisk"
            node_partition = lib_uris.gUriGen.UriMake("CIM_LogicalDisk", partition_name)
        else:
            # The class CIM_LogicalDisk represents a contiguous range of logical blocks
            # that is identifiable by a FileSystem via the Disk's DeviceId (key) field.
            # Each storage extent with the capability of or already hosting a file system
            # is represented as a sub-class of CIM_LogicalDisk.
            # The class CIM_LogicalDisk is the connector between File Systems and Storage Extents

            # [sdiskpart(device='/dev/vda1', mountpoint='/var/lib/docker/containers',
            #            fstype='ext4', opts='rw,seclabel,relatime,data=ordered'),]


            # This does not really work on Windows because WMI expects
            # something like 'Win32_DiskPartition.DeviceID="Disk #0.Partition #0"'
            partition_name = part.device

            node_partition = lib_uris.gUriGen.DiskPartitionUri(partition_name)

        mount_point = part.mountpoint.replace('\\', '/')
        node_mount = lib_uris.gUriGen.DirectoryUri(mount_point)

        # TODO: Check this list.
        if part.fstype != "":
            # partition(device='T:\\\\', mountpoint='T:\\\\', fstype='', opts='cdrom')
            grph.add((node_partition, pc.property_file_system_type, lib_util.NodeLiteral(part.fstype)))
            grph.add((node_mount, pc.property_mount, node_partition))

        if part.opts != "":
            grph.add((node_mount, pc.property_mount_options, lib_util.NodeLiteral(part.opts)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
