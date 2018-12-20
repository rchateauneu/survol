#!/usr/bin/python

"""
WMI: Remote machine partitions
"""

import sys
import lib_common
import lib_util
import lib_wmi
from lib_properties import pc

# If this module is not there, the whole sciprt will not be imported.
import wmi

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
	cgiEnv = lib_common.CgiEnv(can_process_remote = True)
	machineName = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	if lib_util.IsLocalAddress( machineName ):
		machName_or_None = None
		serverBox = lib_common.gUriGen
	else:
		machName_or_None = machineName
		serverBox = lib_common.RemoteBox(machineName)

	try:
		loginImplicit = False # IF FACT, WHY SHOULD IT BE SET ????????
		if loginImplicit or machName_or_None is None:
			# ESSAYER D UTILISER UNE EVENTUELLE CONNECTION PERSISTENTE ?? Non ca ne marche pas !!!!!
			cnnct = wmi.WMI (machineName)
		else:
			# persistent net connection
			# This works:
			# >>> c = wmi.WMI(wmi=wmi.connect_server(server='Titi', namespace="/root/cimv2", user='rchateauneu@hotmail.com', password='xxxx'))

			DEBUG("Explicit WMI connection machineName=%s", machineName )

			cnnct = lib_wmi.WmiConnect(machineName,"/root/cimv2")

			#(wmiUser,wmiPass) = lib_credentials.GetCredentials("WMI",machineName)
			#sys.stderr.write("machineName= %wmiUser=%s\n" % ( machineName, wmiUser ) )
			#cnnct = wmi.WMI(wmi=wmi.connect_server(server=machineName, namespace="/root/cimv2", user=wmiUser, password=wmiPass))

	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("WMI " + machineName + " partitions:" + str(exc) )

	for physical_disk in cnnct.Win32_DiskDrive ():
		node_disk = serverBox.DiskUri( physical_disk.Name.replace('\\','/') )
		grph.add( ( node_disk, pc.property_information, lib_common.NodeLiteral( physical_disk.MediaType ) ) )

		for partition in physical_disk.associators ("Win32_DiskDriveToDiskPartition"):
			for logical_disk in partition.associators ("Win32_LogicalDiskToPartition"):
				# BEWARE: What we call parition is in fact a logical disk.
				# This is not really important for this application,
				# as long as there are two levels in a disk description.
				node_partition = serverBox.DiskPartitionUri( logical_disk.Name )
				grph.add( ( node_partition, pc.property_information, lib_common.NodeLiteral( logical_disk.Description ) ) )

				grph.add( ( node_partition, pc.property_file_system_type, lib_common.NodeLiteral(logical_disk.FileSystem) ) )

				# The logical disk name is the same as the mount point.
				grph.add( ( node_partition, pc.property_partition, node_disk ) )
				grph.add( ( serverBox.DirectoryUri( logical_disk.Name ), pc.property_mount, node_partition ) )

	cgiEnv.OutCgiRdf()
  
if __name__ == '__main__':
	Main()
