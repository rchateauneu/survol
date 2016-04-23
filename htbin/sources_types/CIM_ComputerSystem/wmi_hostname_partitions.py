#!/usr/bin/python

"""
Gets partitions on a local or remote Windows machine, using WMI library.
"""

import sys
import rdflib
import lib_common
from lib_common import pc

try:
	import wmi
except ImportError:
	lib_common.ErrorMessageHtml("wmi library cannot be imported")

# C est particulierement interessant d essayer d unifier notre modele avec WBEM,
# car nous utilisons WMI qui est une sorte de WBEM. Alors il faut prendre garde
# a ne pas perdre d information dans la traduction WMI => Survol => WBEM.


#instance of Win32_DiskDrive
#{
#        BytesPerSector = 512;
#        Capabilities = {3, 4, 10};
#        CapabilityDescriptions = {"Random Access", "Supports Writing", "SMART Notification"};
#        Caption = "ST500DM002-1BD142 ATA Device";
#        ConfigManagerErrorCode = 0;
#        ConfigManagerUserConfig = FALSE;
#        CreationClassName = "Win32_DiskDrive";
#        Description = "Disk drive";
#        DeviceID = "\\\\.\\PHYSICALDRIVE1";
#        FirmwareRevision = "HP73";
#        Index = 1;
#        InterfaceType = "IDE";
#        Manufacturer = "(Standard disk drives)";
#        MediaLoaded = TRUE;
#        MediaType = "Fixed hard disk media";
#        Model = "ST500DM002-1BD142 ATA Device";
#        Name = "\\\\.\\PHYSICALDRIVE1";
#        Partitions = 1;
#        PNPDeviceID = "IDE\\DISKST500DM002-1BD142_______________________HP73____\\5&23F6E727&0&1.0.0";
#        SCSIBus = 1;
#        SCSILogicalUnit = 0;
#        SCSIPort = 1;
#        SCSITargetId = 0;
#        SectorsPerTrack = 63;
#        SerialNumber = "335a535433373244202020202020202020202020";
#        Signature = 1885856125;
#        Size = "500105249280";
#        Status = "OK";
#        SystemCreationClassName = "Win32_ComputerSystem";
#        SystemName = "LONW00052257";
#        TotalCylinders = "60801";
#        TotalHeads = 255;
#        TotalSectors = "976768065";
#        TotalTracks = "15504255";
#        TracksPerCylinder = 255;
#};
#
#instance of Win32_DiskPartition
#{
#        BlockSize = "512";
#        Bootable = FALSE;
#        BootPartition = FALSE;
#        Caption = "Disk #1, Partition #0";
#        CreationClassName = "Win32_DiskPartition";
#        Description = "Installable File System";
#        DeviceID = "Disk #1, Partition #0";
#        DiskIndex = 1;
#        Index = 0;
#        Name = "Disk #1, Partition #0";
#        NumberOfBlocks = "976769024";
#        PrimaryPartition = TRUE;
#        Size = "500105740288";
#        StartingOffset = "1048576";
#        SystemCreationClassName = "Win32_ComputerSystem";
#        SystemName = "LONW00052257";
#        Type = "Installable File System";
#};
#
#instance of Win32_LogicalDisk
#{
#        Access = 0;
#        Caption = "D:";
#        Compressed = FALSE;
#        CreationClassName = "Win32_LogicalDisk";
#        Description = "Local Fixed Disk";
#        DeviceID = "D:";
#        DriveType = 3;
#        FileSystem = "NTFS";
#        FreeSpace = "140379004928";
#        MaximumComponentLength = 255;
#        MediaType = 12;
#        Name = "D:";
#        QuotasDisabled = TRUE;
#        QuotasIncomplete = FALSE;
#        QuotasRebuilding = FALSE;
#        Size = "500105736192";
#        SupportsDiskQuotas = TRUE;
#        SupportsFileBasedCompression = TRUE;
#        SystemCreationClassName = "Win32_ComputerSystem";
#        SystemName = "LONW00052257";
#        VolumeDirty = FALSE;
#        VolumeName = "DATADRIVE1";
#        VolumeSerialNumber = "C8CAF221";
#};

def Main():
	cgiEnv = lib_common.CgiEnv("WMI: Remote machine partitions", platform_regex = "win", can_process_remote = True)
	machineName = cgiEnv.GetId()

	grph = rdflib.Graph()

	try:
		c = wmi.WMI (machineName)
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("WMI " + machineName + " partitions:" + str(exc) )

	for physical_disk in c.Win32_DiskDrive ():
		node_disk = lib_common.gUriGen.DiskUri( physical_disk.Name.replace('\\','/') )
		grph.add( ( node_disk, pc.property_information, rdflib.Literal( physical_disk.MediaType ) ) )

		for partition in physical_disk.associators ("Win32_DiskDriveToDiskPartition"):
			for logical_disk in partition.associators ("Win32_LogicalDiskToPartition"):
				# BEWARE: What we call parition is in fact a logical disk.
				# This is not really important for this application,
				# as long as there are two levels in a disk description.
				node_partition = lib_common.gUriGen.DiskPartitionUri( logical_disk.Name )
				grph.add( ( node_partition, pc.property_information, rdflib.Literal( logical_disk.Description ) ) )

				grph.add( ( node_partition, pc.property_file_system_type, rdflib.Literal(logical_disk.FileSystem) ) )

				# The logical disk name is the same as the mount point.
				grph.add( ( node_partition, pc.property_partition, node_disk ) )
				grph.add( ( lib_common.gUriGen.FileUri( logical_disk.Name ), pc.property_mount, node_partition ) )

	cgiEnv.OutCgiRdf(grph)
  
if __name__ == '__main__':
	Main()
