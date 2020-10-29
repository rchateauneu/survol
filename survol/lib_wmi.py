import os
import re
import sys
import six
import json
import socket
import lib_util
import lib_common
import lib_credentials
import lib_properties
from lib_properties import pc
import lib_kbase

try:
    import wmi
    import pywintypes
    import win32com.client

    # http://sawbuck.googlecode.com/svn/trunk/sawbuck/py/etw/generate_descriptor.py
    # Generate symbols for the WbemScripting module so that we can have symbols
    # for debugging and use constants throughout the file.
    # Without this, win32com.client.constants are not available.
    win32com.client.gencache.EnsureModule('{565783C6-CB41-11D1-8B02-00600806D9B6}',0, 1, 1)
    wmi_imported = True
except ImportError as exc:
    wmi_imported = False
    ERROR("Some modules could not be imported:%s",str(exc))


# TODO: Just a reminder that WMI can run on Linux, in a certain extent.
# https://pypi.python.org/pypi/wmi-client-wrapper


if False:
    if lib_util.isPlatformLinux:
        import wmi_client_wrapper as wmilnx

        wmic = wmilnx.WmiClientWrapper( username="Administrator", password="password", host="192.168.1.149", )

        output = wmic.query("SELECT * FROM Win32_Processor")

################################################################################


def WmiAllNamespacesUrl(hostname_wmi):
    """For namespaces_wmi.py"""
    wmi_moniker = lib_util.BuildWmiMoniker(hostname_wmi)
    wmi_instance_url = lib_util.EntityUrlFromMoniker(wmi_moniker, True, True, True)
    return wmi_instance_url


def NamespaceUrl(nskey, hostname_wmi, class_nam=""):
    """For objtypes_wmi.py. Beware: The class indicates the starting point for displaying the classes of the namespace."""
    wmi_moniker = lib_util.BuildWmiMoniker(hostname_wmi, nskey, class_nam)
    wmiInstanceUrl = lib_util.EntityUrlFromMoniker(wmi_moniker, True, True)
    return wmiInstanceUrl


def ClassUrl(nskey, hostname_wmi, class_nam):
    """For class_wmi.py"""
    wmi_moniker = lib_util.BuildWmiMoniker(hostname_wmi, nskey, class_nam)
    wmi_instance_url = lib_util.EntityUrlFromMoniker(wmi_moniker, True)
    return wmi_instance_url

################################################################################


def GetWmiUserPass(mach_with_back_slashes):
    # WmiConnect cimom=\\\\rchateau-HP\\:. wmiNamspace=aspnet
    clean_mach_nam = mach_with_back_slashes.replace("\\", "")

    #sys.stderr.write("GetWmiUserPass cimom=%s clean_mach_nam=%s\n" % ( machWithBackSlashes, clean_mach_nam ) )

    wmi_user_pass = lib_credentials.GetCredentials("WMI", clean_mach_nam)

    #sys.stderr.write("GetWmiUserPass wmi_user_pass=%s\n" % ( str(wmi_user_pass) ) )

    if wmi_user_pass[0]:
        return clean_mach_nam, wmi_user_pass[0], wmi_user_pass[1]

    # WMI does not do local connection with the local IP.
    try:
        mach_ip = lib_util.GlobalGetHostByName(clean_mach_nam)
    except Exception as exc:
        lib_common.ErrorMessageHtml("GetWmiUserPass: Cannot connect to WMI server:%s" % clean_mach_nam)

    #sys.stderr.write("GetWmiUserPass mach_ip=%s\n" % ( mach_ip ) )

    wmi_user_pass = lib_credentials.GetCredentials("WMI", mach_ip)
    return mach_ip, wmi_user_pass[0], wmi_user_pass[1]


# This works. Before a given version, had to use server="xyz" instead of computer="xyz"
#c = wmi.WMI(computer="titi",user="titi\\rchateauneu@hotmail.com",password="my_hotmail_pass")


def WmiConnect(mach_with_back_slashes, wmi_namspac, throw_if_error=True):
    # sys.stderr.write("WmiConnect cimom=%s wmiNamspace=%s\n" % ( machWithBackSlashes, wmiNamspac ) )
    # WmiConnect cimom=\\\\rchateau-HP\\:. wmiNamspace=aspnet

    if not mach_with_back_slashes or lib_util.IsLocalAddress(mach_with_back_slashes):
        return wmi.WMI(find_classes=False)

    wmi_machine, wmi_user, wmi_pass = GetWmiUserPass(mach_with_back_slashes)

    dict_params = {}
    if wmi_namspac:
        dict_params['namespace'] = wmi_namspac

    if wmi_user:
        dict_params['user'] = wmi_user
        dict_params['password'] = wmi_pass

    # TODO: THIS DOES NOT MAKE SENSE AND SHOULD BE CHANGED LIKE lib_wbem.py.
    if not lib_util.SameHostOrLocal(wmi_machine, None ):
        dict_params['computer'] = wmi_machine

    DEBUG("WmiConnect wmi_machine=%s wmiNamspac=%s dict_params=%s", wmi_machine, wmi_namspac, str(dict_params))

    try:
        conn_wmi = wmi.WMI(**dict_params)
        #sys.stderr.write("WmiConnect after connection\n" )
    except:
        dict_params['password'] = "XXXYYYZZZ" # Security.
        if throw_if_error:
        # Could not connect, maybe the namespace is wrong.
            lib_common.ErrorMessageHtml("WmiConnect Cannot connect to WMI server with params:%s.Exc=%s" % (str(dict_params),str(sys.exc_info())))
        else:
            ERROR("WmiConnect Cannot connect to WMI server with params:%s.Exc=%s", str(dict_params),str(sys.exc_info()))
            return None

    #sys.stderr.write("WmiConnect returning\n" )
    return conn_wmi

################################################################################


def WmiGetClassKeys(wmi_name_space, wmi_class, cimom_srv):
    """Returns the list of a keys of a given WBEM class. This is is used if the key is not given
    for an entity. This could be stored in a cache for better performance."""
    DEBUG("WmiGetClassKeys wmiNameSpace=%s wmiClass=%s cimomSrv=%s", wmi_name_space, wmi_class, cimom_srv)

    try:
        # TODO: Choose the namespace, remove "root\\" at the beginning.
        # wmi.WMI(namespace="aspnet")
        wmi_cnnct = wmi.WMI(cimom_srv)
        wmi_class = getattr(wmi_cnnct, wmi_class)
    except Exception as exc:
        ERROR("WmiGetClassKeys %s %s %s: Caught:%s", cimom_srv, wmi_name_space, wmi_class, str(exc))
        return None

    wmi_keys = wmi_class.keys
    # sys.stderr.write("WmiGetClassKeys keys=%s\n" % ( str(wmi_keys) ) )
    return wmi_keys


def BuildWmiNamespaceClass(entity_namespace, entity_type ):
    """Normally we must find the right namespace, but default value is OK most of times."""
    # TODO: This is the default namespace where all "interesting" classes are.
    # At the moment, this is hard-coded because we have no interest into other namespaces.
    wmi_namespace = "root\\CIMV2"
    # Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
    return wmi_namespace, entity_type, wmi_namespace + ":" + entity_type


def WmiBuildMonikerPath(entity_namespace, entity_type, entity_id ):
    wmi_name_space, wmi_class, full_class_pth = BuildWmiNamespaceClass(entity_namespace, entity_type )

    # sys.stderr.write("WmiBuildMonikerPath wmi_name_space=%s entity_namespace=%s entity_id=%s\n" % (wmi_name_space, entity_namespace, str(entity_id)))

    return full_class_pth + "." + entity_id


def WmiInstanceUrl(entity_namespace, entity_type, entity_id, entity_host):
    # sys.stderr.write("WmiInstanceUrl %s %s %s %s\n" % (entity_namespace, entity_type, entity_id, entity_host))

    wmi_full_path = WmiBuildMonikerPath(entity_namespace, entity_type, entity_id)

    if wmi_full_path is None:
        return None

    # sys.stderr.write("WmiInstanceUrl wmi_full_path=%s\n" % (wmi_full_path))

    # 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
    wmi_moniker = "\\\\" + entity_host + "\\" + wmi_full_path
    wmi_instance_url = lib_util.EntityUrlFromMoniker( wmi_moniker, entity_id == "")

    # sys.stderr.write("WmiInstanceUrl wmi_instance_url=%s\n" % (wmi_instance_url))
    return wmi_instance_url


################################################################################

def NormalHostName(entity_host):
    if entity_host == "":
        # Typically returns "RCHATEAU-HP".
        # Could also use platform.node() or socket.gethostname() or os.environ["COMPUTERNAME"]
        entity_host = socket.gethostname()
    return lib_util.EntHostToIp(entity_host)

# WMI from a Linux box
# http://www.tomsitpro.com/articles/issue-wmi-queries-from-linux,1-3436.html


def GetWmiUrl(entity_host, entity_namespace, entity_type, entity_id):
    """This returns a list of URLS."""
    if not wmi_imported:
        return None

    entity_host = NormalHostName(entity_host)

    # sys.stderr.write("GetWmiUrl NormalHostName=%s ns=%s type=%s id=%s\n" % (entity_host, entity_namespace, entity_type, entity_id))

    # TODO: entity_host = NONE si current.

    if entity_type == "":
        # TODO: In fact this should rather display all classes for this namespace.
        wmi_url = WmiAllNamespacesUrl(entity_host )
    else:
        wmi_url = WmiInstanceUrl(entity_namespace, entity_type, entity_id, entity_host)

    # sys.stderr.write("GetWmiUrl %s %s %s %s wmi_url=%s\n" % (entity_host, entity_namespace, entity_type, entity_id, wmi_url))
    return wmi_url


def WmiTooManyInstances(class_name):
    """These classes have too many members to be listed or even counted, let alone displayed."""
    # TODO: This list Should also include their base classes.
    # TODO: Have a mechanism to stop the process when it takes too long to return.
    return class_name in ['Win32_ComputerSystem', 'PG_ComputerSystem', 'CIM_UnitaryComputerSystem',
                         'CIM_ComputerSystem','CIM_System','CIM_LogicalElement','Win32_UserAccount',
                         'Win32_Group', 'CIM_ManagedSystemElement', 'CIM_Dependency', 'CIM_LogicalFile',
                         'CIM_SoftwareElement', 'CIM_Directory', 'CIM_DataFile']


def GetWmiClassFlagUseAmendedQualifiersn(conn_wmi, class_nam):
    cls_obj = getattr(conn_wmi, class_nam)
    drv = cls_obj.derivation()
    try:
        base_class = drv[0]
    except IndexError:
        base_class = ""
    return GetWmiClassFlagUseAmendedQualifiersAux(conn_wmi, class_nam, base_class)


# This stores the result of a costly operation.
_dict_base_class_to_sub_class = {}


def GetWmiClassFlagUseAmendedQualifiersAux(conn_wmi, class_nam, base_class):
    try:
        subclasses_dict = _dict_base_class_to_sub_class[base_class]
    except KeyError:
        try:
            subclasses = conn_wmi.SubclassesOf(base_class, win32com.client.constants.wbemFlagUseAmendedQualifiers)
            subclasses_dict = {c.Path_.Class: c for c in subclasses}
        except pywintypes.com_error:
            subclasses_dict = {}
        _dict_base_class_to_sub_class[base_class] = subclasses_dict

    try:
        return subclasses_dict[class_nam]
    except KeyError:
        return None


# This returns the map of units for all properties of a class.
# https://msdn.microsoft.com/en-us/library/aa393650%28v=vs.85%29.aspx
#
# "All CIM-compliant implementations must handle a standard set of qualifiers.
# Units
# Data type: string
# Applies to: properties, methods, parameters
# Type of unit in which the associated data item is expressed. The default is NULL.
# For example, a size data item might have a value of "bytes" for Units."
#
#
# There are unit conversions which are specific to WMI.
# Example when displaying a Win32_Process:
# http://rchateau-hp:8000/survol/entity_wmi.py?xid=%5C%5CRCHATEAU-HP%5Croot%5Ccimv2%3A3AWin32_Process.Handle%3D%221988%22
#
# CSCreationClassName Win32_ComputerSystem
# KernelModeTime      407006609 100 nanoseconds
# OtherTransferCount  13745472 bytes
# PageFileUsage       56264 kilobytes
# PeakPageFileUsage   133264 kilobytes
# PeakVirtualSize     315052032 bytes
# PeakWorkingSetSize  116432 kilobytes
# ReadTransferCount   639502009 bytes
# UserModeTime        798881121 100 nanoseconds
# VirtualSize         235409408 bytes
# WorkingSetSize      15052800 bytes
# WriteTransferCount  13204197 bytes
#
# Some properties of the base class do not have an unit although they should.
# See CIM_Process, base class of Win32_Process:
# VirtualSize, PeakWorkingSetSize, PeakVirtualSize have no units.
# On the other hand WorkingSetSize is in "B" as expected.
#
# TODO: To fix this, for an object of type CIM_Process, use OSCreationClassName="Win32_OperatingSystem"
# That is: Use the units of the property of the actual class of the object, not its base class.
#
# Some units could be created:
# "PageFaults" : page / second
# "PageFileUsage" : Page
# "PeakPageFileUsage" : Page
#
def __WmiDictPropertiesUnitNoCache(conn_wmi, class_name):
    theCls = GetWmiClassFlagUseAmendedQualifiersn(conn_wmi, class_name)

    map_prop_units = {}

    # Another approach
    #for qual in prop_obj.Qualifiers_:
    #    sys.stderr.write("        qual=%s => %s \n"%(qual.Name,qual.Value))
    for prop_obj in theCls.Properties_:
        try:
            # sys.stderr.write("    prop_obj.Qualifiers_('Description')=%s\n"%str(prop_obj.Qualifiers_("Description")))
            # sys.stderr.write("    prop_obj.Qualifiers_('Units')=%s\n"%str(prop_obj.Qualifiers_("Units")))
            prop_nam = prop_obj.Name # 'str(prop_obj.Qualifiers_("DisplayName"))'
            unit_nam = str(prop_obj.Qualifiers_("Units"))
            map_prop_units[prop_nam] = unit_nam
            # sys.stderr.write("WmiDictPropertiesUnit prop_nam=%s unit_nam=%s\n"%(prop_nam,unit_nam))

        # except pywintypes.com_error:
        except Exception as exc:
            #sys.stderr.write("WmiDictPropertiesUnit prop_nam=%s caught:%s \n"%(prop_nam,str(exc)))
            pass

    return map_prop_units


# So, this is calculated only once per class, because it does not change,
# and does not depend on the connection, because it is a WMI data.
__cache_wmi_dict_properties_unit = {}


def WmiDictPropertiesUnit(conn_wmi, class_name):
    try:
        map_prop_units = __cache_wmi_dict_properties_unit[class_name]
    except KeyError:
        map_prop_units = __WmiDictPropertiesUnitNoCache(conn_wmi, class_name)
        __cache_wmi_dict_properties_unit[class_name] = map_prop_units
    return map_prop_units


def WmiAddClassQualifiers(grph, conn_wmi, wmi_class_node, class_name, with_props):
    """This adds information to a WMI class."""
    try:
        # No need to print this, at the moment.
        if False:
            klass_descr = str(dir(getattr(conn_wmi, class_name)))
            grph.add((wmi_class_node, lib_common.MakeProp("dir"), lib_common.NodeLiteral(klass_descr)))

            klass_descr = str(getattr(conn_wmi, class_name)._properties)
            grph.add((wmi_class_node, lib_common.MakeProp("_properties"), lib_common.NodeLiteral(klass_descr)))

            klass_descr = str(getattr(conn_wmi, class_name).properties["Description"])
            grph.add((wmi_class_node, lib_common.MakeProp("properties.Description"), lib_common.NodeLiteral(klass_descr)))

            klass_descr = str(getattr(conn_wmi, class_name).property_map)
            # Otherwise it crashes.
            # klassDescrClean = klass_descr.replace("{"," ").replace("}"," ")
            # sys.stderr.write("klass_descr=%s\n"%klass_descr)
            grph.add((wmi_class_node, lib_common.MakeProp("property_map"), lib_common.NodeLiteral(klass_descr.replace("{", " ").replace("}", " "))))

        the_cls = GetWmiClassFlagUseAmendedQualifiersn(conn_wmi, class_name)
        if the_cls:
            # https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/wmi-class-qualifiers
            # Specifies a description of the block for the locale specified by the Locale qualifier.
            # If defined, WMI clients can display the description string to users.
            klass_descr = the_cls.Qualifiers_("Description")
            # Beware, klass_descr is of type "instance".
            str_klass_descr = six.text_type(klass_descr)

            # This might be a value with broken HTML tags such as:
            # "CIM_DataFile is a type ... <B>The behavior ... e returned.<B>"
            str_klass_descr = str_klass_descr.replace("<B>", "")

            grph.add((wmi_class_node, pc.property_information, lib_common.NodeLiteral(str_klass_descr)))

            if with_props:
                for prop_obj in the_cls.Properties_:
                    prop_dsc = six.text_type(prop_obj.Qualifiers_("Description"))

                    # Properties of different origins should not be mixed.
                    # Prefixes the property with a dot, so sorting displays it at the end.
                    # Surprisingly, the dot becomes invisible.
                    grph.add((wmi_class_node, lib_common.MakeProp("." + prop_obj.Name), lib_common.NodeLiteral(prop_dsc)))
        else:
            grph.add((wmi_class_node, pc.property_information, lib_common.NodeLiteral("No description for %s" % class_name)))

        klass_quals = getattr(conn_wmi, class_name).qualifiers
        for kla_qual_key in klass_quals :
            kla_qual_val = klass_quals[kla_qual_key]
            # sys.stderr.write("WmiAddClassQualifiers kla_qual_val=%s / %s\n"%(str(kla_qual_val),str(type(kla_qual_val))))
            if isinstance(kla_qual_val, tuple):
                kla_qual_val = "{ " + ",".join(kla_qual_val) + " }"

            # Some specific properties match an entity class, so we can create a node.
            # IT WORKS BUT IT IS NOT NICE AS IT IS A SEPARATE NODE.
            # We would like to have a clickable URL displayed in a table TD.
            if kla_qual_key == "UUID":
                nodeUUID = lib_common.gUriGen.ComTypeLibUri(kla_qual_val)
                grph.add((wmi_class_node, lib_common.MakeProp(kla_qual_key), nodeUUID))
                continue

            grph.add((wmi_class_node, lib_common.MakeProp(kla_qual_key), lib_common.NodeLiteral(kla_qual_val)))
    except Exception as exc:
        try:
            # Dumped in json so that lists can be appropriately deserialized then displayed.
            err_str = json.dumps(list(exc))
        except:
            # Might have caught: 'com_error' object is not iterable
            err_str = json.dumps("Non-iterable COM Error:"+str(exc))
        grph.add((wmi_class_node, lib_common.MakeProp("WMI Error"), lib_common.NodeLiteral(err_str)))


def ValidClassWmi(class_name):
    """Tells if this class for our ontology is in a given WMI server, whatever the namespace is.
    This is used to display or not, the WMI url associated to a Survol object."""
    tp_split = class_name.split("_")
    tp_prefix = tp_split[0]
    return tp_prefix in ["CIM", "Win32", "WMI"]


def WmiAddClassNode(grph, conn_wmi, wmi_node, entity_host, name_space, class_name, prop):
        wmiurl = GetWmiUrl(entity_host, name_space, class_name, "")
        if wmiurl is None:
            return

        wmi_class_node = lib_common.NodeUrl(wmiurl)

        grph.add((wmi_class_node, prop, wmi_node))

        WmiAddClassQualifiers(grph, conn_wmi, wmi_class_node, class_name, False)
        return wmi_class_node


def WmiBaseClasses(conn_wmi, class_name):
    """
        This returns the base classes of a WMI class.
    """
    # Adds the qualifiers of this class.
    klass_obj = getattr(conn_wmi, class_name)

    # It always work even if there is no object.
    return klass_obj.derivation()


def WmiAddBaseClasses(grph, conn_wmi, wmi_node, entity_host, name_space, class_name):
    """Adds the list of base classes. Returns the list of pairs (name node),
    so it can be matched againt another inheritance tree."""
    pairs_name_node = dict()

    wmi_sub_node = wmi_node

    # It always work even if there is no object.
    for base_klass in WmiBaseClasses(conn_wmi, class_name):
        wmi_class_node = WmiAddClassNode(
            grph, conn_wmi, wmi_sub_node, entity_host, name_space, base_klass, pc.property_cim_subclass)
        pairs_name_node[base_klass] = wmi_class_node
        wmi_sub_node = wmi_class_node
    return pairs_name_node


def EntityToLabelWmi(nam_spac, entity_type_NoNS, entity_id, entity_host):
    """This must return the label of an url "entity_wmi.py".
    For example, the name of a process when the PID (Handle) is given.
    Due to performance problems, consider using a cache.
    Or a default value for some "expensive" classes."""
    # sys.stderr.write("EntityToLabelWmi\n")
    return None


# Survol contains three different ontologies: The ontology of classes defined by Survol,
# and the ontology of WMI and WBEM classes respectively. These three ontologies
# share many different classes and, most importantly, do not contradict.
# For example: The same class defined in two different ontologies might have partly
# different attributes, but the common ones have the same meaning and usage.
# The reason for having three ontologies are:
# - WMI on Windows and OpenLMI (OpenPegasus) on Linux, follow the WBEM standard,
#   and define the most import classes in a computer system.
# - But WBEM standard has limitations:
#   = WQL queries can be very very slow, and tend to return only objects of the same type.
#   = It is not possible define new classes (by creating providers) in a portable manner.
#   = WQL has limitations.
#
# On the other hand:
# - Creating a new class takes a couple of Python lines.
# - A script can return any combinations of objects types.
#
# In the three cases, Survol, WMI and WBEM, ontologies are implemented with a dictionary.
# TODO: How to display the information of associators and references ?
def ExtractWmiOntologyLocal():
    cnn = wmi.WMI()

    map_classes = {}
    map_attributes = {}

    for class_name in cnn.classes:
        cls_obj = getattr(cnn, class_name)

        drv_list = cls_obj.derivation()
        # If this is a top-level class, the derivation list is empty.
        # Otherwise, it is the list of base classes names going to the top.
        if drv_list:
            base_class_name = drv_list[0]
        else:
            base_class_name = ""

        the_cls = GetWmiClassFlagUseAmendedQualifiersAux(cnn, class_name, base_class_name)
        text_descr = ""
        if the_cls:
            try:
                textDsc = the_cls.Qualifiers_("Description")
                text_descr = six.text_type(textDsc)
                # pywintypes.com_error: (-2147352567, 'Exception occurred.', (0, u'SWbemQualifierSet', u'Not found ', None, 0, -2147217406), None)
            except pywintypes.com_error:
                pass

        map_classes[class_name] = {"base_class": base_class_name, "class_description": text_descr, "class_keys_list": []}

        # THIS IS FOR DEBUGGING ONLY.
        if False and class_name == "Win32_Process":
            # ('cls_obj=', < _wmi_class: \\RCHATEAU-HP\ROOT\cimv2:Win32_Process >)
            # ('dir(cls_obj)=',
            #  ['__call__', '__doc__', '__eq__', '__getattr__', '__hash__', '__init__', '__lt__', '__module__',
            #   '__repr__', '__setattr__', '__str__', '_associated_classes', '_cached_associated_classes',
            #   '_cached_methods', '_cached_properties', '_class_name', '_getAttributeNames', '_get_keys', '_instance_of',
            #   '_keys', '_methods', '_namespace', '_properties', 'associated_classes', 'associators', 'derivation', 'id',
            #   'instances', 'keys', 'methods', 'new', 'ole_object', 'path', 'properties', 'property_map', 'put',
            #   'qualifiers', 'query', 'references', 'set', 'watch_for', 'wmi_property'])
            print("cls_obj=", cls_obj)
            print("dir(cls_obj)=", dir(cls_obj))
            print("cls_obj._get_keys()=", cls_obj._get_keys())

            # cls_obj._keys=[u'Handle']
            print("cls_obj._keys=", cls_obj._keys)
            # Keys of this class, i.e. subset of properties which uniquely identify an object. cls_obj.keys=[u'Handle']
            print("cls_obj.keys=", cls_obj.keys)

            # All possible properties of this class: cls_obj.properties=
            # {u'MaximumWorkingSetSize': None, u'CSName': None, u'SessionId': None, u'CSCreationClassName': None,
            # u'Priority': None, u'OtherTransferCount': None, u'VirtualSize': None, u'PrivatePageCount': None,
            # u'Status': None, u'ProcessId': None, u'PeakVirtualSize': None, u'Handle': None, u'Description': None,
            # u'OSCreationClassName': None, u'HandleCount': None, u'QuotaPeakNonPagedPoolUsage': None,
            # u'PeakPageFileUsage': None, u'WriteTransferCount': None, u'MinimumWorkingSetSize': None,
            # u'WindowsVersion': None, u'WorkingSetSize': None, u'WriteOperationCount': None, u'PageFaults': None,
            # u'Name': None, u'InstallDate': None, u'ParentProcessId': None, u'QuotaPeakPagedPoolUsage': None,
            # u'OtherOperationCount': None, u'CommandLine': None, u'PeakWorkingSetSize': None, u'Caption': None,
            # u'QuotaNonPagedPoolUsage': None, u'PageFileUsage': None, u'ReadOperationCount': None,
            # u'TerminationDate': None, u'KernelModeTime': None, u'QuotaPagedPoolUsage': None, u'ThreadCount': None,
            # u'CreationDate': None, u'ExecutionState': None, u'OSName': None, u'ReadTransferCount': None,
            # u'UserModeTime': None, u'CreationClassName': None, u'ExecutablePath': None})
            print("cls_obj.properties=", cls_obj.properties)

            # cls_obj.property_map={}
            print("cls_obj.property_map=", cls_obj.property_map)

            # cls_obj.associated_classes=
            # {u'Win32_ComputerSystem': <_wmi_class: \\RCHATEAU-HP\ROOT\cimv2:Win32_ComputerSystem>,
            # u'Win32_LogonSession': <_wmi_class: \\RCHATEAU-HP\ROOT\cimv2:Win32_LogonSession>,
            # u'Win32_NamedJobObject': <_wmi_class: \\RCHATEAU-HP\ROOT\cimv2:Win32_NamedJobObject>})
            print("cls_obj.associated_classes=", cls_obj.associated_classes)

            # cls_obj.associators()=[]
            print("cls_obj.associators()=", cls_obj.associators())

        # http://timgolden.me.uk/python/wmi/wmi.html
        # A WMI object is uniquely defined by a set of properties which constitute its keys.
        # The function keys() lazily retrieves the keys for this instance or class.
        # ... whereas cls_obj.properties return the properties, that is any attribute of an object of this class.
        # for p in cls_obj.properties:
        for p in cls_obj.keys:
            prop_obj = cls_obj.wmi_property(p)

            if False and class_name == "Win32_Process":
                # p= u'MaximumWorkingSetSize'
                print("p=", p)

                # ('dir(p)=',
                #  ['__add__', '__class__', '__contains__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__',
                #   '__getattribute__', '__getitem__', '__getnewargs__', '__getslice__', '__gt__', '__hash__', '__init__',
                #   '__le__', '__len__', '__lt__', '__mod__', '__mul__', '__ne__', '__new__', '__reduce__', '__reduce_ex__',
                #   '__repr__', '__rmod__', '__rmul__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__',
                #   '_formatter_field_name_split', '_formatter_parser', 'capitalize', 'center', 'count', 'decode', 'encode',
                #   'endswith', 'expandtabs', 'find', 'format', 'index', 'isalnum', 'isalpha', 'isdecimal', 'isdigit',
                #   'islower', 'isnumeric', 'isspace', 'istitle', 'isupper', 'join', 'ljust', 'lower', 'lstrip', 'partition',
                #   'replace', 'rfind', 'rindex', 'rjust', 'rpartition', 'rsplit', 'rstrip', 'split', 'splitlines',
                #   'startswith', 'strip', 'swapcase', 'title', 'translate', 'upper', 'zfill'])
                print("dir(p)=", dir(p))

                # prop_obj=<wmi_property: MaximumWorkingSetSize>
                print("prop_obj=", prop_obj)

                # dir(prop_obj)=['__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattr__',
                # '__getattribute__', '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__',
                # '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'name',
                # 'property', 'qualifiers', 'set', 'type', 'value']
                print("dir(prop_obj)=", dir(prop_obj))

            try:
                prop_dict = map_attributes[prop_obj.name]
            except KeyError:
                prop_dict = {"predicate_type": prop_obj.type, "predicate_domain": []}
                map_attributes[prop_obj.name] = prop_dict

            prop_dict["predicate_domain"].append(class_name)
            map_classes[class_name]["class_keys_list"].append(prop_obj.name)

            # try:
            #     only_read = prop_obj.qualifiers['read']
            # except:
            #     only_read = False
            # # if not only_read:
            # if only_read:
            #     map_attributes[prop_obj.name] = {
            #         "predicate_type": prop_obj.type,
            #         "predicate_domain": class_name }

        # Second enumeration of properties, different style.
        if False and the_cls:
            for propObj in the_cls.Properties_:
                try:
                    map_attributes[propObj.Name]["predicate_description"]
                    continue
                except KeyError:
                    pass
                try:
                    # UnicodeEncodeError: 'ascii' codec can't encode character u'\xa0' in position 178: ordinal not in range(128)
                    propDsc = propObj.Qualifiers_("Description")
                    propTxt = six.text_type(propDsc)
                    map_attributes.get(propObj.Name,{})["predicate_description"] = propTxt
                except pywintypes.com_error:
                    # pywintypes.com_error: (-2147352567, 'Exception occurred.', (0, u'SWbemQualifierSet', u'Not found ', None, 0, -2147217406), None)
                    pass

    return map_classes, map_attributes

################################################################################

# This is a hard-coded list of properties which cannot be displayed.
# They should be stored in the class directory. This is a temporary hack
# until we find a general rule, or find similar properties.
# TODO: Convert this into an image. Find similar properties.
# At least display the type when it happens.
_prp_cannot_be_displayed = {
    "CIM_ComputerSystem": ["OEMLogoBitmap"]
}

# There are unit conversions which are specific to WMI.
# Example when displaying a Win32_Process:
# http://rchateau-hp:8000/survol/entity_wmi.py?xid=%5C%5CRCHATEAU-HP%5Croot%5Ccimv2%3A3AWin32_Process.Handle%3D%221988%22
#
# CSCreationClassName Win32_ComputerSystem
# KernelModeTime      407006609 100 nanoseconds
# OtherTransferCount  13745472 bytes
# PageFileUsage       56264 kilobytes
# PeakPageFileUsage   133264 kilobytes
# PeakVirtualSize     315052032 bytes
# PeakWorkingSetSize  116432 kilobytes
# ReadTransferCount   639502009 bytes
# UserModeTime        798881121 100 nanoseconds
# VirtualSize         235409408 bytes
# WorkingSetSize      15052800 bytes
# WriteTransferCount  13204197 bytes
def UnitConversion(a_flt_value, val_unit):
    try:
        unit_notation = {
            "bytes": "B",
            "kilobytes": "kB"
        }[val_unit]
        return lib_util.AddSIUnit(a_flt_value, unit_notation)
    except KeyError:
        pass

    # Special case needing a conversion. Jeefie.
    if val_unit == "100 nanoseconds":
        return lib_util.AddSIUnit(float(a_flt_value) / 10, "ms")

    # Unknown unit.
    return lib_util.AddSIUnit(a_flt_value, val_unit)


def WmiKeyValues(conn_wmi, obj_wmi, display_none_values, class_name):
    """
        Returns the properties and values of a WMI object (Not a class).
    """

    # This returns the map of units for all properties of a class.
    # Consider using the value of the property "OSCreationClassName",
    # because units properties of base classes are not always documented.
    map_prop_units = WmiDictPropertiesUnit(conn_wmi, class_name)

    for prp_name in obj_wmi.properties:

        # Some common properties are not displayed because the value is cumbersome,
        # and do not bring useful information.
        if prp_name in ["OSName"]:
            continue

        prp_prop = lib_common.MakeProp(prp_name)

        try:
            val_unit = map_prop_units[prp_name]
        except KeyError:
            val_unit = ""

        # className="CIM_ComputerSystem" for example.
        try:
            do_not_display = prp_name in _prp_cannot_be_displayed[class_name]
        except KeyError:
            do_not_display = False

        if do_not_display:
            WARNING("Cannot display:%s", str(getattr(obj_wmi, prp_name)))
            value = "Cannot be displayed"
        else:
            # BEWARE, it could be None.
            value = getattr(obj_wmi, prp_name)

        # Date format: "20189987698769876.97987+000", Universal Time Coordinate (UTC)
        # yyyymmddHHMMSS.xxxxxx +- UUU
        # yyyy represents the year.
        # mm represents the month.
        # dd represents the day.
        # HH represents the hour (in 24-hour format).
        # MM represents the minutes.
        # SS represents the seconds.
        # xxxxxx represents the milliseconds.
        # UUU represents the difference, in minutes, between the local time zone and Greenwich Mean Time (GMT).
        if prp_name in ["CreationDate"]:
            try:
                dt_year = value[0:4]
                dt_month = value[4:6]
                dt_day = value[6:8]
                dt_hour = value[8:10]
                dt_minute = value[10:12]
                dt_second = value[12:14]

                value = "%s-%s-%s %s:%s:%s" % (dt_year, dt_month, dt_day, dt_hour, dt_minute, dt_second)
            except:
                pass

        # The "GUID" property is very specific in WMI.
        if prp_name == "GUID":
            # Example: "{CF185B35-1F88-46CF-A6CE-BDECFBB59B4F}"
            nodeGUID = lib_common.gUriGen.ComTypeLibUri(value)
            yield prp_prop, nodeGUID
            continue

        if prp_name == "Name" and class_name in ["CIM_DataFile", "CIM_Directory"]:
            # sys.stderr.write("WmiKeyValues prp_name=%s className=%s value=%s\n" % (prp_name, className, value))
            # Needed because Sparql does not seem to accept backslashes.
            value_replaced = lib_util.standardized_file_path(str(value))
            #sys.stderr.write("WmiKeyValues prp_name=%s className=%s value=%s value_replaced=%s\n"
            #                 % (prp_name, className, value, value_replaced))
            yield prp_prop, lib_common.NodeLiteral(value_replaced)
        elif isinstance(value, lib_util.scalar_data_types):
            # Special backslash replacement otherwise:
            # "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
            # TODO: Why not CGI escaping ?
            value_replaced = str(value).replace('\\', '\\\\')

            if val_unit:
                value_replaced = UnitConversion(value_replaced, val_unit)
            yield prp_prop, lib_common.NodeLiteral(value_replaced)
        elif isinstance(value, tuple):
            # Special backslash replacement otherwise:
            # "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
            # TODO: Why not CGI escaping ?
            tuple_replaced = [str(one_val).replace('\\', '\\\\') for one_val in value]

            # tuples are displayed as tokens separated by ";". Examples:
            #
            # CIM_ComputerSystem.OEMStringArray
            #" ABS 70/71 60 61 62 63; ;FBYTE#2U3E3X47676J6S6b727H7M7Q7T7W7m8D949RaBagapaqb3bmced3.fH;; BUILDID#13WWHCHW602#SABU#DABU;"
            #
            # CIM_ComputerSystem.Roles
            # "LM_Workstation ; LM_Server ; SQLServer ; NT ; Potential_Browser ; Master_Browser"
            clean_tuple = " ; ".join(tuple_replaced)
            yield prp_prop, lib_common.NodeLiteral(clean_tuple)
        elif value is None:
            if display_none_values:
                yield prp_prop, lib_common.NodeLiteral("None")
        else:
            try:
                ref_moniker = str(value.path())
                ref_instance_url = lib_util.EntityUrlFromMoniker(ref_moniker)
                ref_instance_node = lib_common.NodeUrl(ref_instance_url)
                yield prp_prop, ref_instance_node
            except AttributeError as exc:
                yield prp_prop, lib_common.NodeLiteral(str(exc))


class WmiSparqlCallbackApi:
    def __init__(self):
        # Current host and default namespace.
        self.m_wmi_connection = WmiConnect("", "")
        # Lazy evaluation.
        self.m_classes = None
        self.m_subclasses = None

    def __classes_list(self):
        # Data stored in a cache for later use.
        # If necessary, we cuold restrict this list to the classes which are actively used.
        if self.m_classes == None:
           self.m_classes = self.m_wmi_connection.classes
        return self.m_classes

    def __subclasses_dict(self):
        if self.m_subclasses == None:
            self.m_subclasses = dict()
            for one_class_name in self.__classes_list():
                self.m_subclasses[one_class_name] = self.m_wmi_connection.subclasses_of(one_class_name)

        return self.m_subclasses

    def CallbackSelect(self, grph, class_name, predicate_prefix, filtered_where_key_values):
        INFO("WmiCallbackSelect class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
        assert class_name

        # This comes from such a Sparql triple: " ?variable rdf:type rdf:type"
        if class_name == "type":
            return

        # This comes from such Sparql triples:
        #    ?url_attribute rdf:type rdf:Property
        # or:
        #    ?url_property rdf:type rdf:Property .
        #    ?url_property rdfs:domain survol:CIM_Process .
        #    ?url_property rdfs:seeAlso "WMI" .
        # filtered_where_key_values={u'domain': u'survol:CIM_Process'}
        if class_name == "Property":
            ERROR("WmiCallbackSelect TEST class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
            return

        # HACK: Temporary hard-code !!
        if class_name == "CIM_DataFile" and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/", "\\")
            DEBUG("WmiCallbackSelect REPLACED CIM_DataFile where_key_values=%s", filtered_where_key_values)
        elif class_name == "CIM_Directory" and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/", "\\")
            DEBUG("WmiCallbackSelect REPLACED CIM_Directory where_key_values=%s", filtered_where_key_values)

        wmi_query = lib_util.SplitMonikToWQL(filtered_where_key_values, class_name)
        DEBUG("WmiCallbackSelect wmi_query=%s", wmi_query)

        try:
            wmi_objects = self.m_wmi_connection.query(wmi_query)
        except Exception as exc:
            ERROR("WmiSparqlCallbackApi.CallbackSelect wmi_query='%s': Caught:%s" %(wmi_query, exc))
            raise

        for one_wmi_object in wmi_objects:
            # Path='\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
            object_path = str(one_wmi_object.path())
            DEBUG("one_wmi_object.path=%s", object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, class_name)
            dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral("WMI")

            # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)

            DEBUG("dict_key_values=%s", dict_key_values)
            lib_util.PathAndKeyValuePairsToRdf(grph, object_path, dict_key_values)
            yield object_path, dict_key_values


    # This returns a data structure similar to WmiCallbackSelect
    def CallbackAssociator(
        self,
        grph,
        result_class_name,
        predicate_prefix,
        associator_key_name,
        subject_path):
        # subject_path_node as previously returned by WmiCallbackSelect
        WARNING("WmiCallbackAssociator subject_path=%s result_class_name=%s associator_key_name=%s",
                subject_path,
                result_class_name,
                associator_key_name)
        assert subject_path

        # subject_path = '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="31588"'
        dummy, colon, wmi_path = subject_path.partition(":")
        DEBUG("WmiCallbackAssociator wmi_path=%s", wmi_path)

        # HACK: Temporary hard-code !! Same problem as WmiCallbackSelect
        # TODO: We must quadruple backslashes in Sparql queries.
        if "CIM_DataFile.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            DEBUG("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        elif "CIM_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            DEBUG("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        elif "Win32_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            DEBUG("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        assert wmi_path

        # 'ASSOCIATORS OF {Win32_Process.Handle="1780"} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile'
        # 'ASSOCIATORS OF {CIM_DataFile.Name="c:\\program files\\mozilla firefox\\firefox.exe"} WHERE AssocClass = CIM_ProcessExecutable ResultClass = CIM_Process'
        wmi_query = "ASSOCIATORS OF {%s} WHERE AssocClass=%s ResultClass=%s" % (wmi_path, associator_key_name, result_class_name)

        DEBUG("WmiCallbackAssociator wmi_query=%s", wmi_query)

        wmi_objects = self.m_wmi_connection.query(wmi_query)

        for one_wmi_object in wmi_objects:
            # Path='\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
            object_path = str(one_wmi_object.path())
            DEBUG("WmiCallbackAssociator one_wmi_object.path=%s",object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, result_class_name)
            dict_key_values = {node_key:node_value for node_key, node_value in list_key_values}

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral("WMI")

            # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"
            # p=http://www.w3.org/1999/02/22-rdf-syntax-ns#type
            # o=http://primhillcomputers.com/survol/Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeNodeForSparql(result_class_name)

            DEBUG("WmiCallbackAssociator dict_key_values=%s", dict_key_values)
            lib_util.PathAndKeyValuePairsToRdf(grph, object_path, dict_key_values)
            yield object_path, dict_key_values

    # This returns the classes defined by WMI.
    # Parameters:
    # see_also="WMI"
    # where_key_values={u'rdfs:label': 'CIM_Process'} or {}
    def CallbackTypes(self, grph, see_also, where_key_values):
        WARNING("CallbackTypes see_also=%s where_key_values=%s", see_also, where_key_values)

        # At the moment, the only possible filter is the class name.
        if where_key_values:
            assert len(where_key_values) == 1
            filter_class_name = where_key_values['rdfs:label']
        else:
            filter_class_name = None

        for one_class_name in self.__classes_list():
            if filter_class_name and (one_class_name != filter_class_name):
                continue
            class_path = "WmiClass:" + one_class_name

            dict_key_values = {}
            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_common.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_common.NodeLiteral("WMI")
            dict_key_values[lib_kbase.PredicateType] = lib_kbase.PredicateType
            nodeClassName = lib_common.NodeLiteral(one_class_name)
            dict_key_values[lib_kbase.PredicateLabel] = nodeClassName
            # TODO: Is this useful ?
            dict_key_values[lib_common.NodeLiteral("Name")] = nodeClassName

            class_node = lib_util.NodeUrl(class_path)

            if grph:
                grph.add((class_node, lib_kbase.PredicateType, lib_kbase.PredicateType))

            yield class_path, dict_key_values

    # This returns the base class of each subclass.
    # Luckily, this does not have to return the list of subclasses of each class,
    # otherwise this would not fit into the one-to-one model of Sparql execution in Survol.
    def CallbackTypeTree(self, grph, see_also, class_name, associator_subject):
        assert class_name
        # class_name="CIM_Action"
        if class_name == "CIM_LogicalDevice":
            WARNING("CallbackTypeTree class_name=%s associator_subject=%s", class_name, associator_subject)

        class_path = "WmiClass:" + class_name
        class_node = lib_util.NodeUrl(class_path)
        dict_subclasses = self.__subclasses_dict()
        try:
            list_subclasses = dict_subclasses[class_name]
        except KeyError:
            list_subclasses = []
        for one_subclass_name in list_subclasses:
            if class_name == "CIM_LogicalDevice":
                WARNING("CallbackTypeTree one_subclass_name=%s", one_subclass_name)
            subclass_path = "WmiClass:" + one_subclass_name
            subclass_node = lib_util.NodeUrl(subclass_path)
            dict_key_values = {
                lib_kbase.PredicateSubClassOf: class_node,
                lib_kbase.PredicateLabel: one_subclass_name,
                'Name': one_subclass_name}

            if grph:
                grph.add((subclass_node, lib_kbase.PredicateSubClassOf, class_node))
            yield subclass_path, dict_key_values


class WmiSparqlExecutor:
    def __init__(self):
        # Current host and default namespace.
        self.m_wmi_connection = WmiConnect("", "")

    def SelectObjectFromProperties(self, class_name, filtered_where_key_values):
        INFO("WmiSparqlExecutor.SelectObjectFromProperties class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
        assert class_name

        # HACK: Temporary hard-code !!
        if class_name in ["CIM_DataFile", "CIM_Directory"] and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/", "\\")
            DEBUG("SelectObjectFromProperties REPLACED CIM_DataFile where_key_values=%s", filtered_where_key_values)

        wmi_query = lib_util.SplitMonikToWQL(filtered_where_key_values, class_name)
        sys.stderr.write("SelectObjectFromProperties wmi_query=%s\n" % wmi_query)
        DEBUG("WmiCallbackSelect wmi_query=%s", wmi_query)

        try:
            wmi_objects = self.m_wmi_connection.query(wmi_query)
        except Exception as exc:
            ERROR("WmiSparqlExecutor.SelectObjectFromProperties wmi_query='%s': Caught:%s" % (wmi_query, exc))
            raise

        sys.stderr.write("SelectObjectFromProperties num=%d\n" % len(wmi_objects))
        for one_wmi_object in wmi_objects:
            # The WMI path is not a correct path for Survol: The class could be a derived class of the CIM standard,
            # and the prefix containing the Windows host, must rather contain a Survol agent.
            # Path='\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
            object_path = str(one_wmi_object.path())
            #DEBUG("one_wmi_object.path=%s",object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, class_name)
            dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}

            # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)

            #sys.stderr.write("dict_key_values=%s\n" % str(dict_key_values))
            yield object_path, dict_key_values

    @staticmethod
    def _cleanup_wmi_path(wmi_path):
        # HACK: Temporary hard-code !! Same problem as WmiCallbackSelect
        # TODO: We must quadruple backslashes in Sparql queries.
        if "CIM_DataFile.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\").replace("/", "\\")
            DEBUG("_cleanup_wmi_path wmi_path=%s REPLACED", wmi_path)
        elif "CIM_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\").replace("/", "\\")
            DEBUG("_cleanup_wmi_path wmi_path=%s REPLACED", wmi_path)
        elif "Win32_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\").replace("/", "\\")
            DEBUG("_cleanup_wmi_path wmi_path=%s REPLACED", wmi_path)
        assert wmi_path
        return wmi_path

    def SelectBidirectionalAssociatorsFromObject(self, result_class_name, associator_key_name, wmi_path, role_index):
        # subject_path = '\\RCHATEAU-HP\root\cimv2:Win32_Process.Handle="31588"'
        #sys.stderr.write("SelectAssociatorsFromObject subject_path=%s\n" % wmi_path)
        # dummy, colon, wmi_path = subject_path.partition(":")
        #DEBUG("WmiCallbackAssociator wmi_path=%s", wmi_path)

        wmi_path = self._cleanup_wmi_path(wmi_path)

        # 0 if wmi_path is subject, like ASSOCIATOR OF. Otherwise 1.
        assert role_index in [0, 1]

        wmi_path = self._cleanup_wmi_path(wmi_path)

        reference_class_properties = self.AssociatorKeys(associator_key_name)

        # If reference_class_name="CIM_DirectoryContainsFile", then ['GroupComponent', 'PartComponent']
        sys.stderr.write("reference_class_properties=%s\n" % str(reference_class_properties))
        chosen_role = reference_class_properties[role_index][1]

        # 'ASSOCIATORS OF {Win32_Process.Handle="1780"} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile'
        # 'ASSOCIATORS OF {CIM_DataFile.Name="c:\\program files\\mozilla firefox\\firefox.exe"} WHERE AssocClass = CIM_ProcessExecutable ResultClass = CIM_Process'
        wmi_query = "ASSOCIATORS OF {%s} WHERE AssocClass=%s ResultClass=%s ResultRole=%s" % (
            wmi_path, associator_key_name, result_class_name, chosen_role)

        #DEBUG("WmiCallbackAssociator wmi_query=%s", wmi_query)
        #sys.stderr.write("SelectAssociatorsFromObject wmi_query=%s\n" % wmi_query)

        try:
            wmi_objects = self.m_wmi_connection.query(wmi_query)
        except Exception as exc:
            # Probably com_error
            sys.stderr.write("============================================================\n")
            sys.stderr.write("WmiCallbackAssociator Caught: %s\n" % exc)
            sys.stderr.write("============================================================\n")
            return

        for one_wmi_object in wmi_objects:
            # Path='\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
            object_path = str(one_wmi_object.path())
            #DEBUG("WmiCallbackAssociator one_wmi_object.path=%s",object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, result_class_name)
            dict_key_values = {node_key:node_value for node_key,node_value in list_key_values}

            # s=\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"
            # p=http://www.w3.org/1999/02/22-rdf-syntax-ns#type
            # o=http://primhillcomputers.com/survol/Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeNodeForSparql(result_class_name)

            #DEBUG("WmiCallbackAssociator dict_key_values=%s", dict_key_values)
            yield (object_path, dict_key_values)

    def AssociatorKeys(self, associator_name):
        is_associator = getattr(self.m_wmi_connection, associator_name).qualifiers.get('Association', False)
        assert is_associator

        associator_definition = self.m_wmi_connection._cached_classes(associator_name)
        associator_as_text = str(associator_definition)
        list_keys = []
        for one_line in associator_as_text.split("\n"):
            # "[read: ToSubClass, key] CIM_DataFile ref Antecedent = NULL;"
            match_property = re.match(r".*\] ([A-Za-z_0-9]+) ref ([A-Za-z_0-9]+) ", one_line)
            if match_property:
                list_keys.append((match_property.group(1), match_property.group(2)))
        return list_keys
