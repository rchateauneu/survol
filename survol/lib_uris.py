import os
import sys
import socket
import lib_util

################################################################################

# This assumes that class names are unique: For WBEM and WMI, it always assumes namespace=root/cimv2:
# The other CIM namespaces are not needed here.


def TruncateHostname(host_dns):
    """
    This "fixes" the host name which is not correct in some circumstances.
    WMI wants only the first part of the address on Windows (Same string for OpenPegasus and WMI).
    On Linux apparently, Name="Unknown-30-b5-c2-02-0c-b5-2.home"
    Beware of a normal address such as: "wb-in-f95.1e100.net"
    Similar problem on "darwin" with ".local" .
    See cgiserver.py and also lib_util.HostName()
    """

    host_split = host_dns.split(".")
    if len(host_split) == 2 and host_split[1] == "home":
        host_name = host_split[0]
    else:
        host_name = host_dns
    return host_name


class PathFactory:
    """
        lib_uris.PathFactory().CIM_ComputerSystem(Name="abc.txt"),
        => 'CIM_ComputerSystem.Name=%s' % "abc.txt",
        lib_uris.PathFactory().odbc.dsn(Dsn="DSN=MS Access Database"),
        => 'odbc/dsn.Dsn=DSN~MS Access Database'
    """

    def __init__(self, class_name=None):
        self.m_class_name = class_name

    def __call__(self, *args_call, **kwargs_call):
        entity_id = self.m_class_name + "." + ",".join("%s=%s" % kv_pair for kv_pair in kwargs_call.items())
        return entity_id

    def __getattr__(self, attribute_name):
        concat_class_name = self.m_class_name + "/" + attribute_name if self.m_class_name else attribute_name
        return PathFactory(concat_class_name)


class LocalBox:
    """
    This contains several similar function which create a node from a class name and several arguments.
    These arguments may be passed as a key-value dictionary, or a list of values in the ontology order.
    The script could be "entity.py" and explicitly specified etc...
    """

    def create_entity_path(self, script_path, entity_type, entity_id):
        url_path = self.RootUrl() + script_path + \
                   lib_util.xidCgiDelimiter + self.host_path_prefix() + entity_type + "." + entity_id
        return url_path

    def RootUrl(self):
        return lib_util.uriRoot

    def _build_entity_id(self, entity_type, *entity_id_arr):
        """This works only if the attribute values are in the same order as the ontology."""
        keys = lib_util.OntologyClassKeys(entity_type)

        len_keys = len(keys)
        len_ent_ids = len(entity_id_arr)

        assert len_keys == len_ent_ids
        # TODO: See lib_util.EntityUri which does something similar.
        entity_id = ",".join("%s=%s" % kw_items for kw_items in zip(keys, entity_id_arr))

        return entity_id

    def host_path_prefix(self):
        """
        If the instance is on a remote machine, it returns a prefix containing the host name,
        and this prefix goes before the class name.
        :return:
        """
        return ""

    ###################################################################################
    def node_from_script_path(self, script_path, entity_type, entity_id):
        url_path = self.create_entity_path(script_path, entity_type, entity_id)
        # Depending on the code path, NodeUrl might be called on the result of NodeUrl,
        # and this is not detected because it does not harm, just a waste of CPU.
        return lib_util.NodeUrl(url_path)

    def node_from_path(self, entity_type, entity_id):
        return self.node_from_script_path("/entity.py", entity_type, entity_id)

    def node_from_args(self, entity_type, *entity_id_arr):
        entity_id = self._build_entity_id(entity_type, *entity_id_arr)
        return self.node_from_path(entity_type, entity_id)

    def node_from_script_args(self, path, entity_type, *entity_id_arr):
        entity_id = self._build_entity_id(entity_type, *entity_id_arr)
        return self.node_from_script_path(path, entity_type, entity_id)

    def node_from_dict(self, entity_type, entity_id_dict):
        """
        Example of call
        node_from_dict("CIM_Datafile/portable_executable/section", {"Name": fileName, "Section": sectionName})
        TODO: It would help to specific the entity_type from the current directory.
        So that, when the script is moved, it would not need to be changed.
        For example: UriMakeFromDictCurrentPackage({ "Name" : fileName, "Section" : sectionName })
        Or even: UriMakeFromDictCurrentPackage( Name = fileName, Section = sectionName )
        Or even: UriMakeFromDictCurrentPackage(fileName,sectionName)
        """

        def uri_pair_encode(key_it, val_it):
            try:
                # Maybe this is a derived type from str, encoding the value.
                # TODO: This will be replaced by base64 encoding.
                encoded_val = key_it.ValueEncode(val_it)
                return key_it, encoded_val
            except AttributeError:
                # This is a plain string, no value encoding needed.
                return key_it, val_it

        # TODO: See lib_util.EntityUri which does something similar.
        entity_id = ",".join("%s=%s" % uri_pair_encode(*kw_items) for kw_items in entity_id_dict.items())
        return self.node_from_path(entity_type, entity_id)


    # TODO: Use PathFactory



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
        return self.node_from_args('CIM_Process', str(pid))

    # TODO: Necessaire car CIM_ComputerSystem veut un nom de machine.
    # socket.gethostbyaddr("192.168.1.83")     => ('mymachine.home', [], ['192.168.1.83'])
    # socket.gethostbyaddr("192.168.1.88")     => ('Unknown-30-b5-c2-02-0c-b5-2.home', [], ['192.168.1.88'])
    # socket.gethostbyaddr("192.168.1.81")     => ('WDMyCloudMirror.home', [], ['192.168.1.81'])
    def HostnameUri(self, host_addr):
        # WMI    : CIM_ComputerSystem => WIN32_ComputerSystem
        # OpenLMI: CIM_LogicalElement => CIM_System et CIM_ComputerSystem =>  CIM_UnitaryComputerSystem => PG_ComputerSystem
        # OpenPegasus: Idem.
        host_name = TruncateHostname(host_addr)

        # Hostnames are case-insensitive, RFC4343 https://tools.ietf.org/html/rfc4343
        host_name = host_name.lower()

        return self.node_from_args("CIM_ComputerSystem", host_name)

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
    def SharedLibUri(self, soname):
        """This method should be in a module dedicated to this class, but it is used very often,
        so it is convenient to have it here."""
        return self.node_from_args("CIM_DataFile", lib_util.EncodeUri(soname))

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
    def DiskPartitionUri(self, disk_name):
        """This method should be in a module dedicated to this class, but it is used very often,
        so it is convenient to have it here."""
        return self.node_from_args("CIM_DiskPartition", disk_name)

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
    def DiskUri(self, disk_name):
        """This method should be in a module dedicated to this class, but it is used very often,
        so it is convenient to have it here."""
        return self.node_from_args("CIM_DiskDrive", disk_name)

    # smbshare has the form "//HOST/SHARE" ... but there is a bug in the test HTTP server
    # we are using, as it collapses duplicated slashes "//" into one,
    # because URLs are supposed to be filenames, and therefore normalised.
    # The work-around is to encode slashes.
    # See modules CGIHTTPServer, BaseHTTPServer, CGIHTTPRequestHandler and
    # 'SERVER_SOFTWARE': 'SimpleHTTP/0.6 Python/2.7.10'
    def SmbShareUri(self, smbshare):
        """This method should be in a module dedicated to this class, but it is used very often,
        so it is convenient to have it here."""
        #if smbshare[0:2] == "//":
        #    # Maybe we should cgiescape the whole string.
        #    smbshare = "%2F%2F" + smbshare[2:]
        return self.node_from_args("Win32_Share", smbshare)

    def Win32_NetworkConnectionUri(self, disk_name):
        """This method should be in a module dedicated to this class, but it is used very often,
        so it is convenient to have it here."""
        return self.node_from_args("Win32_NetworkConnection", disk_name)

        # TODO: IN FACT THIS IS SIMPLY A MACHINE. MAYBE WE SHOULD SUBCLASS TYPES ?????
    # OR MAYBE ADD SEVERAL CLASS NAMES ??? "smbserver+hostname" ?
    # OR MAYBE THE ABSTRACT CONCEPT OF A SERVER, POINTING TO THE MACHINE ITSELF?
    def SmbServerUri(self,smbserver):
        return self.node_from_args("smbserver", smbserver)

    def SmbFileUri(self, smbshare, smbfile):
        if smbfile and smbfile[0] != "/":
            fullnam = smbshare + "/" + smbfile
        else:
            fullnam = smbshare + smbfile
        return self.node_from_args("smbfile", fullnam)

    # TODO: Services are also a process. Also, put this in its module.
    def ServiceUri(self, service):
        return self.node_from_args("Win32_Service", service)

    # TODO: This function should be moved to its module.
    def SmbDomainUri(self, smbdomain):
        return self.node_from_args("smbdomain", smbdomain)

    # This class does not represent a physical concept, because a symbol can be defined in several libraries.
    # The use of this logical concept depends on the behaviour of the dynamic linker if it is defined several
    # times in the same binary. If the file is not defined, this is a system call.
    # This concept also works for Python, Perl or any language, depending on the file.
    # TODO: DOES NOT WORK IF REMOTE SYMBOL.
    def SymbolUri(self, symbol_name, path=""):
        # The URL should never contain the chars "<" or ">".
        symbol_name = lib_util.Base64Encode(symbol_name)
        # TODO: Move that to linker_symbol/__init__.py and see sources_types.sql.query.MakeUri
        # TODO: Alphabetical order !!!!
        path = lib_util.standardized_file_path(path)
        return self.node_from_dict("linker_symbol", {"Name": symbol_name, "File": lib_util.EncodeUri(path)})

    # Might be a C++ class or a namespace, as there is no way to differentiate from ELF symbols.
    # This can also be a Pythonor Perl class: This is a logical concept, whose implementation
    # depends on the language of the file path.
    # TODO: Move that to class/__init__.py and see sources_types.sql.query.MakeUri
    def ClassUri(self, class_name, path = ""):
        # The URL should never contain the chars "<" or ">".
        class_name = lib_util.Base64Encode(class_name)
        path = lib_util.standardized_file_path(path)
        return self.node_from_dict("class", {"Name": class_name, "File": lib_util.EncodeUri(path)})

    # CIM_DeviceFile is common to WMI and WBEM.

    # This must be a complete path name.
    # If there is a backslash-L, it will be replaced by "<TABLE>" in graphviz:
    # XML Parsing Error: not well-formed
    def FileUri(self, path):
        path = lib_util.standardized_file_path(path)
        return self.node_from_args("CIM_DataFile", lib_util.EncodeUri(path))

        # TODO: Consider this might be even be more powerful.
        # u'some string'.encode('ascii', 'xmlcharrefreplace')

    # TODO: This function should be moved to its module.
    # If path is terminated by a backslash, it must be stripped otherwise things fail.
    def DirectoryUri(self, path):
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
        path = lib_util.standardized_file_path(path)
        return self.node_from_args("CIM_Directory", lib_util.EncodeUri(path))

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
    def AddrUri(self, addr, socket_port, transport="tcp"):
        # The standard id encodes the port as an integer.
        # But addr.EntityName() displays it with getservbyport
        try:
            socket_port_number = socket.getservbyname(socket_port)
        except:
            socket_port_number = int(socket_port)

        # addr could be "LOCALHOST"
        if lib_util.is_local_address(addr):
            # TODO: Should use the actual IP address.
            addr = "127.0.0.1"

        url = "%s:%d" % (addr, socket_port_number)

        if transport != 'tcp':
            # This will happen rarely.
            url += ":" + transport
        # TODO: THIS IS WHERE WE SHOULD MAYBE ALWAYS USE A RemoteBox().
        return self.node_from_args("addr", url)

    # TODO: Maybe this should be a file, nothing else.
    # TODO: This function should be moved to its module.
    def MemMapUri(self, memmap_path):
        # Because DOT replace "\L" by "<TABLE>".
        # Probably must do that for files also.
        # "xid=memmap:C:\Program Files (x86)Memory mapsoogle\Chrome\Application\39.0.2171.95<TABLE>ocales\fr.pak"
        return self.node_from_args("memmap", lib_util.standardized_memmap_path(memmap_path))

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
    # CIM_Account and CIM_Group not defined on OpenPegasus
    #
    # WMI:
    # Win32_Group: "Distributed COM users","Guests", "Backup Operators" etc...
    # Win32_Account: Win32_Group + Win32_SystemAccount + Win32_UserAccount
    # Win32_UserAccount: "Administrator","Guest","HomeGroupUser$","my_user"
    # Win32_SystemAccount : Very specific to Windows Windows.
    # Win32_GroupUser: "HomeUsers", "Administrator" : Association between Win32_Group and an account
    #
    def UserUri(self, username):
        if lib_util.isPlatformLinux:
            # Its base class is CIM_Account.
            user_tp = "LMI_Account"
        elif lib_util.isPlatformWindows:
            # TODO: DEPRECATED But this is called directly from entity.py.
            # TODO: Should be removed.
            user_tp = "Win32_UserAccount"
        elif lib_util.isPlatformDarwin:
            # CIM_Account is the information held by a SecurityService to track identity and privileges.
            # Common examples of an Account are the entries in a UNIX /etc/passwd file.

            # Temporarily, to avoid entity_type=CIM_Account Caught:No module named CIM_Account
            user_tp = "LMI_Account" # ""CIM_Account"
        else:
            user_tp = "UserUri_invalid_platform_%s" % username

        split_user = username.split("\\")
        if len(split_user) > 1:
            user_host = split_user[0]
            user_only = split_user[1]
        else:
            # This transforms "mymachine.home" into "mymachine"
            user_host = TruncateHostname(lib_util.currentHostname)
            user_only = username
        user_host = user_host.lower() # RFC4343
        # BEWARE: "Name","Domain"
        # node_from_args must take into account the order of the ontology
        usr_uri = self.node_from_args(user_tp, user_only, user_host)
        return usr_uri

    # TODO: This function should be moved to the module of the "group" class.
    def GroupUri(self, groupname):
        if lib_util.isPlatformLinux:
            return self.node_from_args("LMI_Group", groupname)
        else:
            return None

    # TODO: This function should be moved to its module.
    # TODO: At the moment, keys have this structure: {CE4AACFA-3CFD-4028-B2D9-F272314F07C8}
    # But we need a string to loop in the registry: win32con.HKEY_CLASSES_ROOT, "TypeLib".
    # What about the other thnigs in combrowse.py ? "Registered Categories" and "Running Objects" ?
    def ComRegisteredTypeLibUri(self, key_name):
        return self.node_from_args("com/registered_type_lib", lib_util.EncodeUri(key_name))

    # TODO: This function should be moved to its module.
    def ComTypeLibUri(self, file_name):
        return self.node_from_args("com/type_lib", lib_util.EncodeUri(file_name))


gUriGen = LocalBox()


class RemoteBox (LocalBox):
    """For a remote object displayed on the local agent."""
    def __init__(self,mach):
        self.m_mach = mach

    def host_path_prefix(self):
        """This indicates the machine name as a prefix."""
        # TODO: This is deprecated and not reliable: Better relying on the Survol, WMI or WBEM agent url

        # What does WMI:
        # Share            : \\MY-MACHINE\root\cimv2:Win32_Share.Name="ADMIN$"
        # SharedElement    : \\MY-MACHINE\root\CIMV2:Win32_Directory.Name="c:\\windows"
        #
        # By default, the machine name is the agent machine. The default namespace is /root/cimv2.
        return "//" + self.m_mach + ":"


class OtherAgentBox (LocalBox):
    """For remote objects displayed by their corresponding remote agent.
    At the moment, this can only be HTTP. Should be HTTPS also."""
    def __init__(self, url_root_agent):
        self.m_urlRootAgent = url_root_agent

    def RootUrl(self):
        return self.m_urlRootAgent


def MachineBox(mach):
    """mach could be an IP address, a machine name, None, "localhost" etc..."""
    if lib_util.is_local_address(mach):
        the_machine_box = gUriGen
    else:
        the_machine_box = RemoteBox(mach)
    return the_machine_box
