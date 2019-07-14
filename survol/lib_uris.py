import os
import sys
import socket
import lib_util

################################################################################

# This assumes that class names are unique: For WBEM and WMI,
# it always assumes namespace=root/cimv2 : The other CIM namespaces
# have no interest for our usage.

# See lib_util.HostName()
# WMI wants only the first part of the address on Windows (Same string for OpenPegasus and WMI).
# On Linux apparently, Name="Unknown-30-b5-c2-02-0c-b5-2.home"
# Beware of a normal address such as: "wb-in-f95.1e100.net"
# TODO: Fix this !
def TruncateHostname(hostDns):
    hostSplit = hostDns.split(".")
    if len(hostSplit) == 2 and hostSplit[1] == "home":
        # if isPlatformLinux:
        hostName = hostSplit[0]
    else:
        hostName = hostDns
    return hostName

class LocalBox:

    def MakeTheNode(self, entity_type, entity_id):
        return self.MakeTheNodeFromScript( "/entity.py", entity_type, entity_id)

    def RootUrl(self):
        return lib_util.uriRoot

    def MakeTheNodeFromScript(self, path, entity_type, entity_id):
        url = self.RootUrl() + path + lib_util.xidCgiDelimiter + self.TypeMake() + entity_type + "." + entity_id
        # Depending on the code path, NodeUrl is sometimes called recursively, which is not detected
        # because its conversion to a string returns the same URL.
        return lib_util.NodeUrl( url )

    def BuildEntity(self, entity_type, *entity_id_arr):
        # sys.stderr.write("BuildEntity type=%s id_arr=%s Caller=%s\n" % (entity_type, str(entity_id_arr), sys._getframe(1).f_code.co_name ) )

        keys = lib_util.OntologyClassKeys(entity_type)
        #sys.stderr.write("UriMake keys=%s\n" % str(keys) )

        lenKeys = len(keys)
        lenEntIds = len(entity_id_arr)
        if lenKeys < lenEntIds:
            # Append fake temporary keys
            ERROR("BuildEntity entity_type=%s Not enough keys:%s and %s",entity_type,str(keys),str(entity_id_arr))
            keys += [ "Key_%d" % idx for idx in range(lenKeys,lenEntIds) ]
        elif lenKeys > lenEntIds:
            # Not enough values. This is not a problem because of queries returning several objects.
            ERROR("BuildEntity entity_type=%s Not enough values:%s and %s",entity_type,str(keys),str(entity_id_arr))
            # entity_id_arr += [ "Unknown" ] * ( lenKeys - lenEntIds )

        # Sorted keys, same order for Python 2 et 3.
        entity_id = ",".join( "%s=%s" % kwItems for kwItems in zip( keys, entity_id_arr ) )

        return entity_id

    def UriMake(self, entity_type, *entity_id_arr):
        entity_id = self.BuildEntity( entity_type, *entity_id_arr )
        return self.MakeTheNode( entity_type, entity_id )

    def UriMakeFromScript(self, path, entity_type, *entity_id_arr):
        entity_id = self.BuildEntity( entity_type, *entity_id_arr )
        return self.MakeTheNodeFromScript( path, entity_type, entity_id )

    # Example of call
    # UriMakeFromDict("CIM_Datafile/portable_executable/section", { "Name" : fileName, "Section" : sectionName } )
    # TODO: It would help to specific the entity_type from the current directory.
    # So that, when the script is moved, it would not need to be changed.
    # For example: UriMakeFromDictCurrentPackage({ "Name" : fileName, "Section" : sectionName })
    # Or even: UriMakeFromDictCurrentPackage( Name = fileName, Section = sectionName )
    # Or even: UriMakeFromDictCurrentPackage(fileName,sectionName)
    def UriMakeFromDict(self, entity_type, entity_id_dict):
        def UriPairEncode(keyIt,valIt):
            try:
                # Maybe this is a derived type from str, encoding the value.
                encodedVal = keyIt.ValueEncode(valIt)
                # sys.stderr.write("UriPairEncode keyIt=%s typ=%s encodedVal=%s\n"%(keyIt,type(keyIt),encodedVal))
                return (keyIt,encodedVal)
            except AttributeError:
                # sys.stderr.write("UriPairEncode keyIt=%s typ=%s\n"%(keyIt,type(keyIt)))
                # This is a plain str, no value encoding.
                return (keyIt,valIt)

        entity_id = ",".join( "%s=%s" % UriPairEncode(*kwItems) for kwItems in entity_id_dict.items() )
        # sys.stderr.write("UriMakeFromDict entity_id=%s\n"%entity_id)
        return self.MakeTheNode( entity_type, entity_id )

    # This is a virtual method.
    def TypeMake(self):
        return ""

    ###################################################################################
    # TODO: All the following methods return an Uri given the parameters of a class.
    # TODO: They should all be moved to their own module.

    # >>> wmi.WMI().Win32_Process()[0].derivation()
    # (u'CIM_Process', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
    #
    # OpenLMI:
    # CIM_ManagedElement     Instance Names     Instances
    # |--- CIM_ManagedSystemElement     Instance Names     Instances
    # |    |--- CIM_LogicalElement
    # |    |    |--- CIM_EnabledLogicalElement     Instance Names     Instances
    # |    |    |    |--- CIM_Process     Instance Names     Instances
    # |    |    |    |    |--- CIM_UnixProcess     Instance Names     Instances
    # |    |    |    |    |    |--- TUT_UnixProcess     Instance Names     Instances
    #
    # OpenPegasus/Windows:
    # CIM_ManagedElement     Instance Names     Instances
    # |--- CIM_ManagedSystemElement     Instance Names     Instances
    # |    |--- CIM_LogicalElement     Instance Names     Instances
    # |    |    |--- CIM_EnabledLogicalElement     Instance Names     Instances
    # |    |    |    |--- CIM_Process     Instance Names     Instances
    # |    |    |    |    |--- PG_UnixProcess     Instance Names     Instances
    #
    def PidUri(self,pid):
        return self.UriMake('CIM_Process',str(pid))

    # TODO: Necessaire car CIM_ComputerSystem veut un nom de machine.
    # socket.gethostbyaddr("192.168.1.83")     => ('rchateau-HP.home', [], ['192.168.1.83'])
    # socket.gethostbyaddr("192.168.1.88")     => ('Unknown-30-b5-c2-02-0c-b5-2.home', [], ['192.168.1.88'])
    # socket.gethostbyaddr("192.168.1.81")     => ('WDMyCloudMirror.home', [], ['192.168.1.81'])
    def HostnameUri(self,hostAddr):
        # WMI    : CIM_ComputerSystem => WIN32_ComputerSystem
        # OpenLMI: CIM_LogicalElement => CIM_System et CIM_ComputerSystem =>  CIM_UnitaryComputerSystem => PG_ComputerSystem
        # OpenPegasus: Idem.
        # sys.stderr.write("HostnameUri=%s\n" % hostName )
        try:
            hostName = TruncateHostname(hostAddr)
        except:
            exc = sys.exc_info()[1]
            DEBUG("HostnameUri hostAddr=%s. Caught: %s", hostAddr, str(exc) )
            hostName = hostAddr

        # Hostnames are case-insensitive, RFC4343 https://tools.ietf.org/html/rfc4343
        hostName = hostName.lower()

        return self.UriMake("CIM_ComputerSystem",hostName)

    # TODO: THIS WILL NOT WORK IF REMOTE LIB, BECAUSE IT WRAPS A RemoteXXX
    #
    # >>> wmi.WMI().CIM_DataFile.derivation()
    # (u'CIM_LogicalFile', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
    # >>> wmi.WMI().Win32_Directory.derivation()
    # (u'CIM_Directory', u'CIM_LogicalFile', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
    #
    # OpenLMI:
    # CIM_ManagedElement     Instance Names     Instances
    # |--- CIM_ManagedSystemElement     Instance Names     Instances
    # |    |--- CIM_LogicalElement     Instance Names     Instances
    # |    |    |--- CIM_UnixFile     Instance Names     Instances
    # |    |    |    |--- LMI_UnixFile     Instance Names     Instances
    # |    |    |--- CIM_LogicalFile     Instance Names     Instances
    # |    |    |    |--- CIM_DataFile     Instance Names     Instances
    # |    |    |    |    |--- LMI_DataFile     Instance Names     Instances
    # |    |    |    |    |--- LMI_UnixSocket     Instance Names     Instances
    # |    |    |    |--- CIM_DeviceFile     Instance Names     Instances
    # |    |    |    |    |--- CIM_UnixDeviceFile     Instance Names     Instances
    # |    |    |    |    |    |--- LMI_UnixDeviceFile     Instance Names     Instances
    # |    |    |    |--- CIM_Directory     Instance Names     Instances
    # |    |    |    |    |--- CIM_UnixDirectory     Instance Names     Instances
    # |    |    |    |    |    |--- LMI_UnixDirectory     Instance Names     Instances
    # |    |    |    |--- CIM_FIFOPipeFile     Instance Names     Instances
    # |    |    |    |    |--- LMI_FIFOPipeFile     Instance Names     Instances
    # |    |    |    |--- CIM_SymbolicLink     Instance Names     Instances
    # |    |    |    |    |--- LMI_SymbolicLink     Instance Names     Instances
    #
    # OpenPegasus/Windows:
    # Nothing
    #
    def SharedLibUri(self,soname):
        return self.UriMake("CIM_DataFile", lib_util.EncodeUri(soname) )

    # For a partition. Display the mount point and IO performance.
    # WMI
    #    CIM_ManagedSystemElement
    #        CIM_LogicalElement
    #            CIM_LogicalDevice
    #                CIM_StorageExtent
    # |   |   |    |--- CIM_DiskPartition
    # |   |   |    |    |--- Win32_DiskPartition
    #
    # OpenLMI:
    # |--- CIM_LogicalElement
    # |   |--- CIM_LogicalDevice
    # |   |   |--- CIM_GenericDiskPartition
    # |   |   |    |--- CIM_DiskPartition
    # |   |   |    |    |--- LMI_DiskPartition
    def DiskPartitionUri(self,disk_name):
        return self.UriMake("CIM_DiskPartition",disk_name)
        # return self.UriMake("CIM_LogicalDisk",disk_name)

    # For a hard-disk.
    # WMI
    #    CIM_ManagedSystemElement
    #        CIM_LogicalElement
    #            CIM_LogicalDevice,
    #                CIM_MediaAccessDevice
    # |   |   |    |--- CIM_DiskDrive
    # |   |   |    |    |--- Win32_DiskDrive
    #
    #
    # OpenPegasus: Nothing
    #
    # OpenLMI:
    # |--- CIM_LogicalElement
    # |   |--- CIM_LogicalDevice
    # |   |   |--- CIM_StorageExtent
    # |   |   |   |--- CIM_MediaPartition
    # |   |   |   |   |--- CIM_MediaAccessDevice
    # |   |   |   |   |    |--- CIM_CDROMDrive
    # |   |   |   |   |    |--- CIM_DVDDrive
    # |   |   |   |   |    |--- CIM_DiskDrive
    # |   |   |   |   |    |    |--- LMI_DiskDrive
    #
    def DiskUri(self,disk_name):
        return self.UriMake("CIM_DiskDrive",disk_name)

    # smbshare has the form "//HOST/SHARE" ... but there is a bug in the test HTTP server
    # we are using, as it collapses duplicated slashes "//" into one,
    # because URLs are supposed to be filenames, and therefore normalised.
    # The work-around is to encode slashes.
    # See modules CGIHTTPServer, BaseHTTPServer, CGIHTTPRequestHandler and
    # 'SERVER_SOFTWARE': 'SimpleHTTP/0.6 Python/2.7.10'
    def SmbShareUri(self,smbshare):
        if smbshare[0:2] == "//":
            # Maybe we should cgiescape the whole string.
            smbshare = "%2F%2F" + smbshare[2:]
        return self.UriMake("smbshr", smbshare)

    # TODO: IN FACT THIS IS SIMPLY A MACHINE. MAYBE WE SHOULD SUBCLASS TYPES ?????
    # OR MAYBE ADD SEVERAL CLASS NAMES ??? "smbserver+hostname" ?
    # OR MAYBE THE ABSTRACT CONCEPT OF A SERVER, POINTING TO THE MACHINE ITSELF?
    def SmbServerUri(self,smbserver):
        return self.UriMake("smbserver", smbserver)

    def SmbFileUri(self,smbshare,smbfile):
        if smbfile and smbfile[0] != "/":
            fullnam = smbshare + "/" + smbfile
        else:
            fullnam = smbshare + smbfile
        return self.UriMake("smbfile", fullnam )

    # TODO: Services are also a process. Also, put this in its module.
    def ServiceUri(self,service):
        return self.UriMake("Win32_Service", service)

    # TODO: This function should be moved to its module.
    def SmbDomainUri(self,smbdomain):
        return self.UriMake("smbdomain", smbdomain)

    # Purely abstract, because a symbol can be defined in several libraries.
    # Its use depend on the behaviour of the dynamic linker if it is defined several
    # times in the same binary. If the file is not defined, this is a system call.
    # TODO: DOES NOT WORK IF REMOTE SYMBOL.
    def SymbolUri(self,symbol_name, path = ""):
        # The URL should never contain the chars "<" or ">".
        symbol_name = lib_util.Base64Encode(symbol_name)
        # TODO: Move that to linker_symbol/__init__.py and see sources_types.sql.query.MakeUri
        # TODO: Alphabetical order !!!!
        path = path.replace("\\","/") # TODO: Use normpath()
        return self.UriMakeFromDict("linker_symbol", { "Name" : symbol_name, "File" : lib_util.EncodeUri(path) } )

    # Might be a C++ class or a namespace, as there is no way to differentiate from ELF symbols.
    # TODO: Move that to class/__init__.py and see sources_types.sql.query.MakeUri
    def ClassUri(self,class_name, path = ""):
        # The URL should never contain the chars "<" or ">".
        class_name = lib_util.Base64Encode(class_name)
        path = path.replace("\\","/") # TODO: Use normpath()
        return self.UriMakeFromDict("class", { "Name" : class_name, "File" : lib_util.EncodeUri(path) } )

    # CIM_DeviceFile is common to WMI and WBEM.

    # This must be a complete path name.
    # If there is a backslash-L, it will be replaced by "<TABLE>" in graphviz:
    # XML Parsing Error: not well-formed
    # Location: http://127.0.0.1/Survol/survol/entity.py?xid=file:C%3A%5CUsers%5Crchateau%5CAppData%5CLocal%5CMicrosoft%5CWindows%5CExplorer%5CThumbCacheToDelete%5Cthm9798.tmp
    def FileUri(self,path):
        path = path.replace("\\","/") # TODO: Use normpath()
        return self.UriMake("CIM_DataFile", lib_util.EncodeUri(path))

        # TODO: Consider this might be even be more powerful.
        # u'some string'.encode('ascii', 'xmlcharrefreplace')

    # TODO: This function should be moved to its module.
    # If path is terminated by a backslash, it must be stripped otherwise things fail.
    def DirectoryUri(self,path):
        # Normalize a pathname by collapsing redundant separators and up-level references
        # so that A//B, A/B/, A/./B and A/foo/../B all become A/B.
        # This string manipulation may change the meaning of a path that contains symbolic links.
        # On Windows, it converts forward slashes to backward slashes.
        path = os.path.normpath(path)
        # Backslashes are a real problem everywhere.
        # On top of that, escaping the backslash is not enough because strings are sometimes truncated for display.
        # Better have our own "canonical" notation for filenames, so replace them.
        # If needed, they can always be replaced by a normal slash.
        #
        path = path.replace("\\","/")
        return self.UriMake( "CIM_Directory" , lib_util.EncodeUri(path))

    # This creates a node for a socket, so later it can be merged with the same socket.
    #
    # TODO: PROBLEM: How can it be merged with the same address but described "from the other side" ??
    # TODO: WE MUST ADD IN ITS PROPERTY, THE ALLEGED NODE "FROM THE OTHER SIDE".
    # TODO: Move this to sources_types/addr/__init__.py
    # MAYBE IT IS NOT ENOUGH (BUT SO ELEGANT), IF THIS IS THE REMOTE NODE, TO USE THE REMOTE HOST,
    # BECAUSE IT WOULD FORBID ANY INVESTIGATION FROM ANOTHER MACHINE ??
    #
    # If the port is known, we could wrap the associated service in a Python script.
    # On the other hand, it forces the usage of a service.
    # We do not put it in a specific module because it is used everywhere and is unavoidable.
    def AddrUri(self,addr,socketPort,transport="tcp"):
        # The standard id encodes the port as an integer.
        # But addr.EntityName() displays it with getservbyport
        try:
            socketPortNumber = socket.getservbyname(socketPort)
        except:
            socketPortNumber = int(socketPort)

        # addr could be "LOCALHOST"
        if lib_util.IsLocalAddress(addr):
            # hostName, aliases, _ = socket.gethostbyaddr(hstAddr)
            # TODO: Should use the actual IP address.
            addr = "127.0.0.1"

        url = "%s:%d" % (addr,socketPortNumber)

        if transport != 'tcp':
            # This will happen rarely.
            url += ":" + transport
        # TODO: THIS IS WHERE WE SHOULD MAYBE ALWAYS USE A RemoteBox().
        return self.UriMake("addr",url)

    # TODO: Maybe this should be a file, nothing else.
    # TODO: This function should be moved to its module.
    def MemMapUri(self,memmap_path):
        # Because DOT replace "\L" by "<TABLE>".
        # Probably must do that for files also.
        # "xid=memmap:C:\Program Files (x86)Memory mapsoogle\Chrome\Application\39.0.2171.95<TABLE>ocales\fr.pak"
        return self.UriMake("memmap",memmap_path.replace('\\','/') )

    # TODO: This function should be moved to its module.
    # Win32_Account:    Domain    Name
    #
    # >>> wmi.WMI().Win32_UserAccount()[0].derivation()
    # (u'Win32_Account', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
    # >>> wmi.WMI().Win32_Group()[0].derivation()
    # (u'Win32_Account', u'CIM_LogicalElement', u'CIM_ManagedSystemElement')
    #
    # CIM_Account:     CreationClassName     Name     SystemCreationClassName     SystemName     Namespace
    #
    # OpenLMI:
    # CIM_ManagedElement     Instance Names     Instances
    # |--- CIM_ManagedSystemElement     Instance Names     Instances
    # |    |--- CIM_LogicalElement
    # |    |    |--- CIM_EnabledLogicalElement     Instance Names     Instances
    # |    |    |    |--- CIM_Account     Instance Names     Instances
    # |    |    |    |    |--- LMI_Account     Instance Names     Instances
    #
    # CIM_ManagedElement     Instance Names     Instances
    # |--- CIM_Collection     Instance Names     Instances
    # |    |--- CIM_Group     Instance Names     Instances
    # |    |    |--- LMI_Group     Instance Names     Instances
    #
    # OpenPegasus/Windows:
    # CIM_Account et CIM_Group pas definis sur OpenPegasus
    #
    # WMI:
    # Win32_Group: "Distributed COM users","Guests", "Backup Operators" etc...
    # Win32_Account: Win32_Group + Win32_SystemAccount + Win32_UserAccount
    # Win32_UserAccount: "Administrator","Guest","HomeGroupUser$","rchateau"
    # Win32_SystemAccount : Tres intern a Windows, on peut laisser de cote.
    # Win32_GroupUser: "HomeUsers", "Administrator" : Association entre Win32_Group et un account
    #
    def UserUri(self,username):
        if lib_util.isPlatformLinux:
            userTp = "LMI_Account"
        elif lib_util.isPlatformWindows:
            # TODO: DEPRECATED But this is called directly from entity.py.
            # TODO: Should be removed.
            userTp = "Win32_UserAccount"
        else:
            userTp = "xxxxx"

        splitUser = username.split("\\")
        if len(splitUser) > 1:
            userHost = splitUser[0]
            userOnly = splitUser[1]
        else:
            # This transforms "rchateau-hp.home" into "rchateau-hp"
            userHost = TruncateHostname(lib_util.currentHostname)
            userOnly = username
        userHost = userHost.lower() # RFC4343
        # BEWARE: "Name","Domain"
        # UriMake must take into account the order of the ontology
        usrUri = self.UriMake(userTp,userOnly,userHost)
        DEBUG("UserUri usrUri=%s",str(usrUri))
        return usrUri

    # TODO: This function should be moved to its module.
    def GroupUri(self,groupname):
        if lib_util.isPlatformLinux:
            return self.UriMake("LMI_Group",groupname)
        else:
            return None

    # TODO: This function should be moved to its module.
    # TODO: At the moment, keys have this structure: {CE4AACFA-3CFD-4028-B2D9-F272314F07C8}
    # But we need a string to loop in the registry: win32con.HKEY_CLASSES_ROOT, "TypeLib".
    # What about the other thnigs in combrowse.py ? "Registered Categories" and "Running Objects" ?
    def ComRegisteredTypeLibUri(self, keyName ):
        return self.UriMake("com/registered_type_lib", lib_util.EncodeUri(keyName) )

    # TODO: This function should be moved to its module.
    def ComTypeLibUri(self, fileName ):
        return self.UriMake("com/type_lib", lib_util.EncodeUri(fileName) )

    ###################################################################################

gUriGen = LocalBox()

# For a remote object displayed on the local agent.
class RemoteBox (LocalBox):
    def __init__(self,mach):
        self.m_mach = mach

    def TypeMake(self):
        return self.m_mach + "@"

# For remote objects displayed by their corresponding remote agent.
# At the moment, this can only be HTTP. Should be HTTPS also.
class OtherAgentBox (LocalBox):
    def __init__(self,urlRootAgent):
        self.m_urlRootAgent = urlRootAgent

    # No need to change the host because the object
    # will be local to its agent.
    # TODO: Adding a host in the url is a dangerous idea,
    # because it is the same object displayed a remote agent.

    def RootUrl(self):
        return self.m_urlRootAgent


# mach could be an IP address, a machine name, None, "localhost" etc...
def MachineBox(mach):
    if lib_util.IsLocalAddress(mach):
        theMachineBox = LocalBox()
    else:
        theMachineBox = RemoteBox(mach)
    return theMachineBox
