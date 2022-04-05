__author__ = "Remi Chateauneu"
__copyright__ = "Copyright 2020-2021, Primhill Computers"
__license__ = "GPL"

import os
import re
import sys
import six
import json
import socket
import logging

import lib_uris
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
    win32com.client.gencache.EnsureModule('{565783C6-CB41-11D1-8B02-00600806D9B6}', 0, 1, 1)
    wmi_imported = True
except ImportError as exc:
    wmi_imported = False
    logging.error("Some modules could not be imported:%s", str(exc))


if False:
    if lib_util.isPlatformLinux:
        # Some notes about using WMI on a Linux box.
        # http://www.tomsitpro.com/articles/issue-wmi-queries-from-linux,1-3436.html
        # https://pypi.python.org/pypi/wmi-client-wrapper
        import wmi_client_wrapper as wmilnx
        wmic = wmilnx.WmiClientWrapper(username="Administrator", password="password", host="192.168.1.149", )
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


def _get_wmi_user_pass(mach_with_back_slashes):
    # WmiConnect cimom=\\\\mymachine\\:. wmiNamspace=aspnet
    clean_mach_nam = mach_with_back_slashes.replace("\\", "")

    wmi_user_pass = lib_credentials.GetCredentials("WMI", clean_mach_nam)

    if wmi_user_pass[0]:
        return clean_mach_nam, wmi_user_pass[0], wmi_user_pass[1]

    # WMI does not do local connection with the local IP.
    try:
        mach_ip = lib_util.GlobalGetHostByName(clean_mach_nam)
    except Exception as exc:
        lib_common.ErrorMessageHtml("GetWmiUserPass: Cannot connect to WMI server:%s. %s" % (clean_mach_nam, exc))

    wmi_user_pass = lib_credentials.GetCredentials("WMI", mach_ip)
    return mach_ip, wmi_user_pass[0], wmi_user_pass[1]


# This works. Before a given version, had to use server="xyz" instead of computer="xyz"
# c = wmi.WMI(computer="titi",user="titi\\john.smith@hotmail.com",password="my_hotmail_pass")


def WmiConnect(mach_with_back_slashes, wmi_namspac, throw_if_error=True):
    # WmiConnect cimom=\\\\mymachine\\:. wmiNamspace=aspnet

    if not mach_with_back_slashes or lib_util.is_local_address(mach_with_back_slashes):
        return wmi.WMI(find_classes=False)

    wmi_machine, wmi_user, wmi_pass = _get_wmi_user_pass(mach_with_back_slashes)

    dict_params = {}
    if wmi_namspac:
        dict_params['namespace'] = wmi_namspac

    if wmi_user:
        dict_params['user'] = wmi_user
        dict_params['password'] = wmi_pass

    # TODO: THIS DOES NOT MAKE SENSE AND SHOULD BE CHANGED LIKE lib_wbem.py.
    if not lib_util.same_host_or_local(wmi_machine, None):
        dict_params['computer'] = wmi_machine

    logging.debug("WmiConnect wmi_machine=%s wmiNamspac=%s dict_params=%s", wmi_machine, wmi_namspac, str(dict_params))

    try:
        conn_wmi = wmi.WMI(**dict_params)
    except Exception as exc:
        dict_params['password'] = "XXXYYYZZZ"  # Security.
        error_message = "Cannot connect to WMI server with params:%s. Exc=%s", str(dict_params), str(exc)
        if throw_if_error:
            # Could not connect, maybe the namespace is wrong.
            lib_common.ErrorMessageHtml(error_message)
        else:
            logging.error(error_message)
            return None

    return conn_wmi


################################################################################


def WmiGetClassKeys(wmi_name_space, wmi_class, cimom_srv):
    """Returns the list of a keys of a given WBEM class. This is is used if the key is not given
    for an entity. This could be stored in a cache for better performance."""
    logging.debug("WmiGetClassKeys wmiNameSpace=%s wmiClass=%s cimomSrv=%s", wmi_name_space, wmi_class, cimom_srv)

    try:
        # TODO: Choose the namespace, remove "root\\" at the beginning.
        # wmi.WMI(namespace="aspnet")
        wmi_cnnct = wmi.WMI(cimom_srv)
        wmi_class = getattr(wmi_cnnct, wmi_class)
    except Exception as exc:
        logging.error("WmiGetClassKeys %s %s %s: Caught:%s", cimom_srv, wmi_name_space, wmi_class, str(exc))
        return None

    wmi_keys = wmi_class.keys
    return wmi_keys


def BuildWmiNamespaceClass(entity_namespace, entity_type):
    """Normally we must find the right namespace, but default value is OK most of times."""
    # TODO: This is the default namespace where all "interesting" classes are.
    # At the moment, this is hard-coded because we have no interest into other namespaces.
    wmi_namespace = "root\\CIMV2"
    # Normally we should check if this class is defined in this cimom. For the moment, we assume, yes.
    return wmi_namespace, entity_type, wmi_namespace + ":" + entity_type


def WmiBuildMonikerPath(entity_namespace, entity_type, entity_id):
    wmi_name_space, wmi_class, full_class_pth = BuildWmiNamespaceClass(entity_namespace, entity_type)

    return full_class_pth + "." + entity_id


def WmiInstanceUrl(entity_namespace, entity_type, entity_id, entity_host):
    wmi_full_path = WmiBuildMonikerPath(entity_namespace, entity_type, entity_id)

    if wmi_full_path is None:
        return None

    # 'https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"'
    wmi_moniker = "\\\\" + entity_host + "\\" + wmi_full_path
    wmi_instance_url = lib_util.EntityUrlFromMoniker(wmi_moniker, entity_id == "")

    return wmi_instance_url


################################################################################

def NormalHostName(entity_host):
    """
    This typically returns "MY_MACHINE".
    It could also use platform.node() or socket.gethostname() or os.environ["COMPUTERNAME"]
    """
    if entity_host == "":
        entity_host = socket.gethostname()
    return lib_util.EntHostToIp(entity_host)


def GetWmiUrl(entity_host, entity_namespace, entity_type, entity_id):
    """
    This returns an URL associated to an instance or a class. Display purpose.
    """
    if not wmi_imported:
        return None

    entity_host = NormalHostName(entity_host)

    # TODO: entity_host = NONE si current.

    if entity_type == "":
        # TODO: In fact this should rather display all classes for this namespace.
        wmi_url = WmiAllNamespacesUrl(entity_host)
    else:
        wmi_url = WmiInstanceUrl(entity_namespace, entity_type, entity_id, entity_host)

    return wmi_url


def WmiTooManyInstances(class_name):
    """
    These classes have too many members to be displayed, listed or even counted.
    Therefore they must accessed with great care, and never enumerated.
    """
    # TODO: This list Should also include their base classes.
    # TODO: Have a mechanism to stop the process when it takes too long to return.
    return class_name in ['Win32_ComputerSystem', 'PG_ComputerSystem', 'CIM_UnitaryComputerSystem',
                          'CIM_ComputerSystem', 'CIM_System', 'CIM_LogicalElement', 'Win32_UserAccount',
                          'Win32_Group', 'CIM_ManagedSystemElement', 'CIM_Dependency', 'CIM_LogicalFile',
                          'CIM_SoftwareElement', 'CIM_Directory', 'CIM_DataFile']


def _get_wmi_class_flag_use_amended_qualifiers(conn_wmi, class_nam):
    """
    This gets the amended qualifiers if this class by fetch the base class and getting its subclasses
    with the flag wbemFlagUseAmendedQualifiers, and now het the original - now derived - class.
    This is intricated but no other way to find the qualifiers of a class.
    """
    cls_obj = getattr(conn_wmi, class_nam)
    drv = cls_obj.derivation()
    try:
        base_class = drv[0]
    except IndexError:
        base_class = ""
    return _get_wmi_class_flag_use_amended_qualifiers_aux(conn_wmi, class_nam, base_class)


# This stores the result of a costly operation.
_dict_base_class_to_sub_class = {}


def _get_wmi_class_flag_use_amended_qualifiers_aux(conn_wmi, class_nam, base_class):
    """
    This returns the list of base classes of the input class.
    It uses an internal cache for speed.
    This could probably be done with derivation().
    """
    try:
        subclasses_dict = _dict_base_class_to_sub_class[base_class]
    except KeyError:
        try:
            # wbemFlagUseAmendedQualifiers WMI to return class amendment data along with the base class definition.
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
# http://mymachine:8000/survol/entity_wmi.py?xid=%5C%5CMYMACHINE%5Croot%5Ccimv2%3A3AWin32_Process.Handle%3D%221988%22
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
def __wmi_dict_properties_unit_no_cache(conn_wmi, class_name):
    the_cls = _get_wmi_class_flag_use_amended_qualifiers(conn_wmi, class_name)

    map_prop_units = {}

    # Another approach
    # for qual in prop_obj.Qualifiers_:
    #    sys.stderr.write("        qual=%s => %s \n"%(qual.Name,qual.Value))

    # This enumerates all properties of a class and return a dict for the unit of each them if there is any.
    for prop_obj in the_cls.Properties_:
        try:
            prop_nam = prop_obj.Name  # 'str(prop_obj.Qualifiers_("DisplayName"))'
            unit_nam = str(prop_obj.Qualifiers_("Units"))
            map_prop_units[prop_nam] = unit_nam
            # sys.stderr.write("WmiDictPropertiesUnit prop_nam=%s unit_nam=%s\n"%(prop_nam,unit_nam))

        # except pywintypes.com_error:
        except Exception as exc:
            # logging.debug("prop_nam=%s caught:%s " % (prop_nam, str(exc)))
            pass

    return map_prop_units


# So, this is calculated only once per class, because it does not change,
# and does not depend on the connection, because it is a WMI data.
__cache_wmi_dict_properties_unit = {}


def WmiDictPropertiesUnit(conn_wmi, class_name):
    """
    Same as __cache_wmi_dict_properties_unit but with a cache because of speed.
    """
    try:
        map_prop_units = __cache_wmi_dict_properties_unit[class_name]
    except KeyError:
        map_prop_units = __wmi_dict_properties_unit_no_cache(conn_wmi, class_name)
        __cache_wmi_dict_properties_unit[class_name] = map_prop_units
    return map_prop_units


def WmiAddClassQualifiers(grph, conn_wmi, wmi_class_node, class_name, with_props):
    """This adds information to a WMI class."""
    logging.debug("class_name=%s", class_name)
    try:
        # No need to print this, at the moment.
        if False:
            klass_descr = str(dir(getattr(conn_wmi, class_name)))
            grph.add((wmi_class_node, lib_common.MakeProp("dir"), lib_util.NodeLiteral(klass_descr)))

            klass_descr = str(getattr(conn_wmi, class_name)._properties)
            grph.add((wmi_class_node, lib_common.MakeProp("_properties"), lib_util.NodeLiteral(klass_descr)))

            klass_descr = str(getattr(conn_wmi, class_name).properties["Description"])
            grph.add((wmi_class_node, lib_common.MakeProp("properties.Description"), lib_util.NodeLiteral(klass_descr)))

            klass_descr = str(getattr(conn_wmi, class_name).property_map)
            # Otherwise it crashes.
            klass_descr_dlean = klass_descr.replace("{"," ").replace("}"," ")
            grph.add((wmi_class_node, lib_common.MakeProp("property_map"), lib_util.NodeLiteral(klass_descr_dlean)))

        the_cls = _get_wmi_class_flag_use_amended_qualifiers(conn_wmi, class_name)
        if the_cls:
            # https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/wmi-class-qualifiers
            # Specifies a description of the block for the locale specified by the Locale qualifier.
            # If defined, WMI clients can display the description string to users.
            try:
                klass_descr = the_cls.Qualifiers_("Description")
            except Exception as wmi_exc:
                klass_descr = "No description for class " + class_name + ":" + str(wmi_exc)
                logging.warning("Caught:%s", wmi_exc)

            # Beware, klass_descr is of type "instance".
            str_klass_descr = six.text_type(klass_descr)

            # This might be a value with broken HTML tags such as:
            # "CIM_DataFile is a type ... <B>The behavior ... e returned.<B>"
            str_klass_descr = str_klass_descr.replace("<B>", "")

            grph.add((wmi_class_node, pc.property_information, lib_util.NodeLiteral(str_klass_descr)))

            if with_props:
                for prop_obj in the_cls.Properties_:
                    try:
                        prop_dsc = six.text_type(prop_obj.Qualifiers_("Description"))
                    except Exception as wmi_exc:
                        prop_dsc = "No description for property " + prop_obj.Name + ":" + str(wmi_exc)
                        logging.warning("Caught:%s", wmi_exc)

                    # Properties of different origins should not be mixed.
                    # Prefixes the property with a dot, so sorting displays it at the end.
                    # Surprisingly, the dot becomes invisible.
                    grph.add((wmi_class_node, lib_common.MakeProp("." + prop_obj.Name), lib_util.NodeLiteral(prop_dsc)))
        else:
            grph.add(
                (wmi_class_node, pc.property_information, lib_util.NodeLiteral("No description for %s" % class_name)))

        klass_quals = getattr(conn_wmi, class_name).qualifiers
        for kla_qual_key in klass_quals:
            kla_qual_val = klass_quals[kla_qual_key]
            if isinstance(kla_qual_val, tuple):
                kla_qual_val = "{ " + ",".join(kla_qual_val) + " }"

            # Some specific properties match an entity class, so we can create a node.
            # IT WORKS BUT IT IS NOT NICE AS IT IS A SEPARATE NODE.
            # We would like to have a clickable URL displayed in a table TD.
            if kla_qual_key == "UUID":
                nodeUUID = lib_uris.gUriGen.ComTypeLibUri(kla_qual_val)
                grph.add((wmi_class_node, lib_common.MakeProp(kla_qual_key), nodeUUID))
                continue

            grph.add((wmi_class_node, lib_common.MakeProp(kla_qual_key), lib_util.NodeLiteral(kla_qual_val)))
    except Exception as wmi_exc:
        try:
            # Dumped in json so that lists can be appropriately deserialized then displayed.
            err_str = json.dumps(list(wmi_exc))
        except:
            # Might have caught: 'com_error' object is not iterable
            err_str = json.dumps("Non-iterable COM Error:" + str(wmi_exc))
        grph.add((wmi_class_node, lib_common.MakeProp("WMI Error"), lib_util.NodeLiteral(err_str)))


def ValidClassWmi(class_name):
    """
    Tells if this class for our ontology is in a given WMI server, whatever the namespace is.
    This is used to display or not, the WMI url associated to a Survol object.
    This is not an absolute rule.
    """
    return class_name.startswith(("CIM_", "Win32_", "WMI_"))


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
    """
    Adds the list of base classes. Returns the list of pairs (base_class_name => node),
    so it can be matched againt another inheritance tree.
    """
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
    """
    This must return the label of an url based on "entity_wmi.py".
    For example, the name of a process when the PID (Handle) is given.
    Due to performance problems, consider using a cache.
    Or a default value for some "expensive" classes.

    At the moment, a default value is used.
    """

    logging.warning("Implement this: entity_id=%s" % entity_id)
    return None


# _build_wmi_path_from_survol_path
def reformat_path_for_wmi(survol_path):
    """
    Paths for Survol and WMI have basically the same structure: 'class.key=value,key=value' etc...
    WMI is a bit more picky because the arguments must be enclosed in double-quotes.
    It would be possible to have the same constraints in Survol, but the important information
    are the classes, the keys and the unquoted values, so this reformatting just
    reformats the unchanged existing information about the instances.
    It is used in SelectBidirectionalAssociatorsFromObject.
    """

    # key-value pairs are separated by commas.
    class_name, entity_id_dict = lib_util.SplitPath(survol_path)

    # This rebuilds a path for WMI with arguments enclosed in double-quotes.
    wmi_path = class_name + "." + ",".join(
        ('%s="%s"' % (prop_key, prop_value) for prop_key, prop_value in entity_id_dict.items())
    )
    return wmi_path



def _convert_wmi_type_to_xsd_type(predicate_type_name):
    """
    This converts a WMI type name to the equivalent XSD type, as a string.
    Later, the conversion to a 'real' XSD type is straightforward.
    The point of this conversion is that it does not need rdflib.

    WMI types: https://powershell.one/wmi/datatypes
    RDF types: https://rdflib.readthedocs.io/en/stable/rdf_terms.html
    """
    wmi_type_to_xsd = {
        'string': "survol_string", # rdflib.namespace.XSD.string
        'boolean': 'survol_boolean',
        'datetime': 'survol_dateTime',
        'sint64': 'survol_integer',
        'sint32': 'survol_integer',
        'sint16': 'survol_integer',
        'sint8': 'survol_integer',
        'uint64': 'survol_integer',
        'uint32': 'survol_integer',
        'uint16': 'survol_integer',
        'uint8': 'survol_integer',
        'real64': 'survol_double',
        'real32': 'survol_double',
    }
    try:
        return wmi_type_to_xsd[predicate_type_name.lower()]
    except KeyError:
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

is_done = False


def extract_specific_ontology_wmi():
    """
    This returns a tuple of two maps.
    - A map of class names to various properties including their base class name,
    i.e. the first element of their derivation, and the list of their properties.
    - A map of properties to their attributes.
    """
    global is_done
    if is_done:
        # This is possible only if testing internal calls.
        logging.critical("Should be called once only during a process'lifetime.")
    is_done = True

    cnn = wmi.WMI()

    list_plain_classes = {}
    list_associations = {}

    def wmi_string_to_str(wmi_string):
        if not lib_util.is_py3:
            assert isinstance(wmi_string, unicode)
            wmi_string = wmi_string.encode()
            assert isinstance(wmi_string, str)
        return wmi_string

    logging.info("first pass on classes")
    for class_name in cnn.classes:
        logging.debug("class_name=%s" % class_name)
        wmi_class_obj = getattr(cnn, class_name)
        class_name = wmi_string_to_str(class_name)

        try:
            is_association = wmi_class_obj.qualifiers['Association']
        except KeyError:
            is_association = False

        if is_association:
            # Contains for example "Win32_SessionProcess", "Win32_System_Processes"
            list_associations[class_name] = wmi_class_obj
        else:
            # For example "Win32_Process"
            list_plain_classes[class_name] = wmi_class_obj

    map_classes = {}
    map_attributes = {}

    logging.info("second pass on classes")
    for class_name, wmi_class_obj in list_plain_classes.items():
        logging.debug("class_name=%s" % class_name)
        drv_list = wmi_class_obj.derivation()
        # If this is a top-level class, the derivation list is empty.
        # Otherwise, it is the list of base classes names going to the top.
        if drv_list:
            # No meed to add all base classes, because they can be explored by going from one base class to the next.
            base_class_name = drv_list[0]
        else:
            base_class_name = ""

        the_cls = _get_wmi_class_flag_use_amended_qualifiers_aux(cnn, class_name, base_class_name)

        # Now, a pass to get the descriptions of the class and its properties. It does not always work.
        text_descr = ""
        props_text_descr = {}
        if the_cls:
            try:
                text_dsc = the_cls.Qualifiers_("Description")
                text_descr = six.text_type(text_dsc)
                # pywintypes.com_error: (-2147352567, 'Exception occurred.',
                # (0, u'SWbemQualifierSet', u'Not found ', None, 0, -2147217406), None)
            except pywintypes.com_error as wmi_exc:
                prop_dsc = "No WMI description for class " + class_name + ":" + str(wmi_exc)
                logging.error("Caught: %s", wmi_exc)
                #pass

            for prop_obj in the_cls.Properties_:
                try:
                    # TODO: Get units with str(prop_obj.Qualifiers_("Units")) ??
                    prop_dsc = six.text_type(prop_obj.Qualifiers_("Description"))
                except Exception as wmi_exc:
                    prop_dsc = "No WMI description for property " + prop_obj.Name + ":" + str(wmi_exc)
                    logging.error("Property:%s Caught:%s", prop_obj.Name, wmi_exc)
                props_text_descr[prop_obj.Name] = prop_dsc

        map_classes[class_name] = {
            "class_description": text_descr,
            "class_keys_list": [], # These are the WMI keys
            "non_key_properties_list": [] # These are the WMI properties
        }
        if base_class_name:
            # Maybe this is an empty string, then do not add it,.
            map_classes[class_name]["base_class"] = base_class_name

        def store_prop_name(prop_obj):
            prop_obj_name = wmi_string_to_str(prop_obj.name)
            assert isinstance(prop_obj_name, str)
            logging.debug("prop_obj_name=%s" % prop_obj_name)
            try:
                prop_dict = map_attributes[prop_obj_name]
            except KeyError:
                clean_type_name = wmi_string_to_str(prop_obj.type)
                if not clean_type_name.startswith("ref:"):
                    # Other possible values: "ref:__Provider", "ref:Win32_LogicalFileSecuritySetting",
                    # "ref:Win32_ComputerSystem",
                    # "ref:CIM_DataFile", "ref:__EventConsumer", "ref:CIM_LogicalElement",
                    # "ref:CIM_Directory" but also "ref:Win32_Directory".
                    # "Win32_DataFile" never appears.

                    # Sometimes the datatype is wrongly cased: "string", "String, "STRING".
                    clean_xsd_type_name = _convert_wmi_type_to_xsd_type(clean_type_name)
                    if clean_xsd_type_name is None:
                        logging.warning("Unknown WMI type=%s Property=%s" % (clean_type_name, prop_obj_name))
                        return None
                    clean_type_name = clean_xsd_type_name

                # At this stage, the type name is consistent for WMI, WBEM or Survol.
                assert isinstance(clean_type_name, str)

                try:
                    prop_dsc = props_text_descr[prop_obj.name]
                except KeyError:
                    prop_dsc = "No description for property:" + prop_obj.name
                prop_dict = {
                    "predicate_type": clean_type_name,
                    "predicate_domain": [],
                    "predicate_description": prop_dsc}
                map_attributes[prop_obj_name] = prop_dict

            assert isinstance(class_name, str)
            prop_dict["predicate_domain"].append(class_name)
            return prop_obj_name

        # http://timgolden.me.uk/python/wmi/wmi.html
        # A WMI object is uniquely defined by a set of properties which constitute its keys.
        # The function keys() lazily retrieves the keys for this instance or class.
        # ... whereas cls_obj.properties return the properties, that is any attribute of an object of this class.
        # for p in cls_obj.properties:
        for the_key in wmi_class_obj.keys:
            prop_obj = wmi_class_obj.wmi_property(the_key)
            prop_obj_name = store_prop_name(prop_obj)
            map_classes[class_name]["class_keys_list"].append(prop_obj_name)

        for the_prop in wmi_class_obj.properties:
            prop_obj = wmi_class_obj.wmi_property(the_prop)
            prop_obj_name = store_prop_name(prop_obj)
            if prop_obj_name is not None:
                map_classes[class_name]["non_key_properties_list"].append(prop_obj_name)

    # Examples of WMI associators:
    # class_name=CIM_DirectoryContainsFile
    #     the_key=GroupComponent tp=ref:CIM_Directory
    #     the_key=PartComponent tp=ref:CIM_DataFile
    # class_name=Win32_SessionConnection
    #     the_key=Antecedent tp=ref:Win32_ServerSession
    #     the_key=Dependent tp=ref:Win32_ServerConnection
    # class_name=Win32_SystemUsers
    #     the_key=GroupComponent tp=ref:Win32_ComputerSystem
    #     the_key=PartComponent tp=ref:Win32_UserAccount
    # class_name=Win32_COMApplicationClasses
    #     the_key=GroupComponent tp=ref:Win32_COMApplication
    #     the_key=PartComponent tp=ref:Win32_COMClass
    # class_name=Win32_SystemServices
    #     the_key=GroupComponent tp=ref:Win32_ComputerSystem
    #     the_key=PartComponent tp=ref:Win32_Service
    # class_name=Win32_ApplicationCommandLine
    #     the_key=Antecedent tp=ref:Win32_ApplicationService
    #     the_key=Dependent tp=ref:Win32_CommandLineAccess
    # class_name=Win32_GroupInDomain
    #     the_key=GroupComponent tp=ref:Win32_NTDomain
    #     the_key=PartComponent tp=ref:Win32_Group
    # class_name=Win32_ClassicCOMApplicationClasses
    #     the_key=GroupComponent tp=ref:Win32_DCOMApplication
    #     the_key=PartComponent tp=ref:Win32_ClassicCOMClass
    # class_name=Win32_ShareToDirectory
    #     the_key=Share tp=ref:Win32_Share
    #     the_key=SharedElement tp=ref:CIM_Directory
    # class_name=Win32_SubDirectory
    #     the_key=GroupComponent tp=ref:Win32_Directory
    #     the_key=PartComponent tp=ref:Win32_Directory
    # class_name=CIM_ProcessExecutable
    #     the_key=Antecedent tp=ref:CIM_DataFile
    #     the_key=Dependent tp=ref:CIM_Process
    """
    These relations are not oriented: Without the property name, it is not possible 
    to determine which object is what, in a triple like this one:
    <file> CIM_ProcessExecutable <process>
    
    Because special characters are allowed in Sparql terms, two properties are create for each associator.
    For example:
    CIM_ProcessExecutable.Antecedent domain=CIM_DataFile range=CIM_Process
    CIM_ProcessExecutable.Dependent domain=CIM_Process range=CIM_DataFile
    This is possible only if there are two classes in the associator, which is always the case (or zero classes).
    """

    logging.info("pass on associators")
    for associator_name, wmi_class_obj in list_associations.items():
        # For example: associator_name="Win32_SessionProcess".

        def key_to_dotted_property(the_key):
            prop_obj = wmi_class_obj.wmi_property(the_key)
            class_name_as_type = wmi_string_to_str(prop_obj.type)
            # All properties point to instances of plain classes which must have been created in the previous loop.
            if not class_name_as_type.startswith("ref:"):
                raise Exception("Invalid key type:%s", class_name_as_type)
            _, _, referenced_class_name = class_name_as_type.partition(":")

            prop_obj_name = store_prop_name(prop_obj)
            if referenced_class_name in list_associations:
                raise Exception("Class %s should not be in associations" % referenced_class_name)
            if referenced_class_name not in list_plain_classes:
                raise Exception("Class %s referenced by %s is not defined" % (referenced_class_name, associator_name))

            # For example: "CIM_ProcessExecutable.Antecedent"
            full_property_name = associator_name + "." + prop_obj_name
            return class_name_as_type, referenced_class_name, full_property_name

        if len(wmi_class_obj.keys) != 2:
            # There should be two classes in the associator, but sometines it is empty.
            logging.warning("Unexpected keys number for class %s: %s" % (associator_name, str(wmi_class_obj.keys)))
            continue

        try:
            # For example, wmi_class_obj.keys = ["Antecedent", "Precedent"]
            class_as_type_a, class_name_a, property_a = key_to_dotted_property(wmi_class_obj.keys[0])
            class_as_type_b, class_name_b, property_b = key_to_dotted_property(wmi_class_obj.keys[1])
        except Exception as exc:
            logging.warning("Caught:" + str(exc))
            continue

        # Check existence of both classes before adding double property.
        if class_name_a not in map_classes:
            logging.warning("Non-existent class %s cannot get property %s" % (class_name_a, property_b))
            continue
        if class_name_b not in map_classes:
            logging.warning("Non-existent class %s cannot get property %s" % (class_name_b, property_a))
            continue

        map_classes[class_name_a]["non_key_properties_list"].append(property_b)
        map_classes[class_name_b]["non_key_properties_list"].append(property_a)

        # Class names as type by WMI are prefixed with the string "ref:", this convention is kept in Survol.
        # This must be later truncated because in RDF, this becomes the node of the class.
        assert class_as_type_a.startswith("ref:")
        assert class_as_type_b.startswith("ref:")
        assert isinstance(class_name_a, str)
        assert isinstance(class_name_b, str)
        map_attributes[property_a] = {"predicate_type": class_as_type_a, "predicate_domain": [class_name_b]}
        map_attributes[property_b] = {"predicate_type": class_as_type_b, "predicate_domain": [class_name_a]}

        #logging.error("map_attributes=%s" % str(map_attributes.keys()))
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
# http://mymachine:8000/survol/entity_wmi.py?xid=%5C%5CMYMACHINE%5Croot%5Ccimv2%3A3AWin32_Process.Handle%3D%221988%22
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
            logging.warning("Cannot display:%s", str(getattr(obj_wmi, prp_name)))
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
            nodeGUID = lib_uris.gUriGen.ComTypeLibUri(value)
            yield prp_prop, nodeGUID
            continue

        if prp_name == "Name" and class_name in ["CIM_DataFile", "CIM_Directory"]:
            # sys.stderr.write("WmiKeyValues prp_name=%s className=%s value=%s\n" % (prp_name, className, value))
            # TODO: This hard-code is needed because Sparql does not seem to accept backslashes.
            value_replaced = lib_util.standardized_file_path(str(value))
            # sys.stderr.write("WmiKeyValues prp_name=%s className=%s value=%s value_replaced=%s\n"
            #                 % (prp_name, className, value, value_replaced))
            yield prp_prop, lib_util.NodeLiteral(value_replaced)
        elif isinstance(value, lib_util.scalar_data_types):
            # Special backslash replacement otherwise:
            # "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
            # TODO: Why not CGI escaping ?
            value_replaced = str(value).replace('\\', '\\\\')

            if val_unit:
                value_replaced = UnitConversion(value_replaced, val_unit)
            yield prp_prop, lib_util.NodeLiteral(value_replaced)
        elif isinstance(value, tuple):
            # Special backslash replacement otherwise:
            # "NT AUTHORITY\\\\NetworkService" displayed as "NT AUTHORITYnd_0etworkService"
            # TODO: Why not CGI escaping ?
            tuple_replaced = [str(one_val).replace('\\', '\\\\') for one_val in value]

            # tuples are displayed as tokens separated by ";". Examples:
            #
            # CIM_ComputerSystem.OEMStringArray
            # " ABS 70/71 60 61 62 63; ;FBYTE#2U3E3X47676J6S6b727H7M7Q7T7W7m8D949RaBagapaqb3bmced3.fH;; BUILDID#13WWHCHW602#SABU#DABU;"
            #
            # CIM_ComputerSystem.Roles
            # "LM_Workstation ; LM_Server ; SQLServer ; NT ; Potential_Browser ; Master_Browser"
            clean_tuple = " ; ".join(tuple_replaced)
            yield prp_prop, lib_util.NodeLiteral(clean_tuple)
        elif value is None:
            if display_none_values:
                yield prp_prop, lib_util.NodeLiteral("None")
        else:
            try:
                ref_moniker = str(value.path())
                ref_instance_url = lib_util.EntityUrlFromMoniker(ref_moniker)
                ref_instance_node = lib_common.NodeUrl(ref_instance_url)
                yield prp_prop, ref_instance_node
            except AttributeError as exc:
                yield prp_prop, lib_util.NodeLiteral(str(exc))


# TODO: DEPRECATED CLASS
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
        logging.info("WmiCallbackSelect class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
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
            logging.error("WmiCallbackSelect TEST class_name=%s where_key_values=%s", class_name,
                          filtered_where_key_values)
            return

        # HACK: Temporary hard-code !!
        if class_name == "CIM_DataFile" and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/", "\\")
            logging.debug("WmiCallbackSelect REPLACED CIM_DataFile where_key_values=%s", filtered_where_key_values)
        elif class_name == "CIM_Directory" and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/", "\\")
            logging.debug("WmiCallbackSelect REPLACED CIM_Directory where_key_values=%s", filtered_where_key_values)

        wmi_query = lib_util.SplitMonikToWQL(filtered_where_key_values, class_name)
        logging.debug("WmiCallbackSelect wmi_query=%s", wmi_query)

        try:
            wmi_objects = self.m_wmi_connection.query(wmi_query)
        except Exception as exc:
            logging.error("WmiSparqlCallbackApi.CallbackSelect wmi_query='%s': Caught:%s" % (wmi_query, exc))
            raise

        for one_wmi_object in wmi_objects:
            # Path='\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"'
            object_path = str(one_wmi_object.path())
            logging.debug("one_wmi_object.path=%s", object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, class_name)
            dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_util.NodeLiteral("WMI")

            # s=\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)

            logging.debug("dict_key_values=%s", dict_key_values)
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
        logging.critical("THIS IS DEPRECATED")
        # subject_path_node as previously returned by WmiCallbackSelect
        logging.warning("WmiCallbackAssociator subject_path=%s result_class_name=%s associator_key_name=%s",
                        subject_path,
                        result_class_name,
                        associator_key_name)
        assert subject_path

        # subject_path = '\\MYMACHINE\root\cimv2:Win32_Process.Handle="31588"'
        dummy, colon, wmi_path = subject_path.partition(":")
        logging.debug("WmiCallbackAssociator wmi_path=%s", wmi_path)

        # HACK: Temporary hard-code !! Same problem as WmiCallbackSelect
        # TODO: We must quadruple backslashes in Sparql queries.
        if "CIM_DataFile.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            logging.debug("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        elif "CIM_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            logging.debug("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        elif "Win32_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\")
            logging.debug("WmiCallbackAssociator wmi_path=%s REPLACED", wmi_path)
        assert wmi_path

        # 'ASSOCIATORS OF {Win32_Process.Handle="1780"} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile'
        # 'ASSOCIATORS OF {CIM_DataFile.Name="c:\\program files\\mozilla firefox\\firefox.exe"} WHERE AssocClass = CIM_ProcessExecutable ResultClass = CIM_Process'
        wmi_query = "ASSOCIATORS OF {%s} WHERE AssocClass=%s ResultClass=%s" % (wmi_path, associator_key_name, result_class_name)

        logging.debug("WmiCallbackAssociator wmi_query=%s", wmi_query)

        wmi_objects = self.m_wmi_connection.query(wmi_query)

        for one_wmi_object in wmi_objects:
            # Path='\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"'
            object_path = str(one_wmi_object.path())
            logging.debug("WmiCallbackAssociator one_wmi_object.path=%s", object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, result_class_name)
            dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}

            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_util.NodeLiteral("WMI")

            # s=\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"
            # p=http://www.w3.org/1999/02/22-rdf-syntax-ns#type
            # o=http://primhillcomputers.com/survol/Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeNodeForSparql(result_class_name)

            logging.debug("WmiCallbackAssociator dict_key_values=%s", dict_key_values)
            lib_util.PathAndKeyValuePairsToRdf(grph, object_path, dict_key_values)
            yield object_path, dict_key_values

    # This returns the classes defined by WMI.
    # Parameters:
    # see_also="WMI"
    # where_key_values={u'rdfs:label': 'CIM_Process'} or {}
    def CallbackTypes(self, grph, see_also, where_key_values):
        logging.warning("CallbackTypes see_also=%s where_key_values=%s", see_also, where_key_values)

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
            dict_key_values[lib_kbase.PredicateIsDefinedBy] = lib_util.NodeLiteral("WMI")
            # Add it again, so the original Sparql query will work.
            dict_key_values[lib_kbase.PredicateSeeAlso] = lib_util.NodeLiteral("WMI")
            dict_key_values[lib_kbase.PredicateType] = lib_kbase.PredicateType
            nodeClassName = lib_util.NodeLiteral(one_class_name)
            dict_key_values[lib_kbase.PredicateLabel] = nodeClassName
            # TODO: Is this useful ?
            dict_key_values[lib_util.NodeLiteral("Name")] = nodeClassName

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
            logging.warning("CallbackTypeTree class_name=%s associator_subject=%s", class_name, associator_subject)

        class_path = "WmiClass:" + class_name
        class_node = lib_util.NodeUrl(class_path)
        dict_subclasses = self.__subclasses_dict()
        try:
            list_subclasses = dict_subclasses[class_name]
        except KeyError:
            list_subclasses = []
        for one_subclass_name in list_subclasses:
            if class_name == "CIM_LogicalDevice":
                logging.warning("CallbackTypeTree one_subclass_name=%s", one_subclass_name)
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
        logging.info("class_name=%s where_key_values=%s", class_name, filtered_where_key_values)
        assert class_name

        # FIXME: HACK: Needed because back-slashes are a pain in Sparql queries.
        # FIXME: Should be done for all attributes which are path names.
        if class_name in ["CIM_DataFile", "CIM_Directory"] and "Name" in filtered_where_key_values:
            filnam = filtered_where_key_values["Name"]
            filtered_where_key_values["Name"] = filnam.replace("/", "\\")
            logging.debug("REPLACED CIM_DataFile where_key_values=%s", filtered_where_key_values)

        wmi_query = lib_util.SplitMonikToWQL(filtered_where_key_values, class_name)
        logging.debug("wmi_query=%s" % wmi_query)

        try:
            wmi_objects = self.m_wmi_connection.query(wmi_query)
        except Exception as exc:
            logging.error("wmi_query='%s': Caught:%s" % (wmi_query, exc))
            raise

        # FIXME: select * from CIM_DiskDrive
        # FIXME: ... might return:
        # FIXME: \\MYMACHINE\root\cimv2:Win32_DiskDrive.DeviceID="\\\\.\\PHYSICALDRIVE0"
        # FIXME:
        # FIXME: "Win32_DiskDrive" is derived class of "CIM_DiskDrive"
        # FIXME: "Win32_DiskDrive" has the property "DeviceID" but "CIM_DiskDrive" has none.
        # FIXME:
        # FIXME: Several possibilities:
        # FIXME:
        # FIXME: - Remove the path of a different class, i.e. of a derived class.
        # FIXME: - Remove the path if different class and the base class do not have their properties.
        # FIXME: - Convert the path to the base class if the base class has this property.
        # FIXME: - Returned the derived object: This means sticking to WMI inheritance model.
        # FIXME:
        # FIXME:

        logging.debug("class_name=%s num=%d" % (class_name, len(wmi_objects)))
        for one_wmi_object in wmi_objects:
            # The WMI path is not a correct path for Survol: The class could be a derived class of the CIM standard,
            # and the prefix containing the Windows host, must rather contain a Survol agent.
            # Path='\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"'
            object_path = str(one_wmi_object.path())

            # DEBUG    root:lib_wmi.py:1025 object_path=['__doc__', '__eq__', '__getattr__', '__hash__', '__init__',
            # '__lt__', '__module__', '__rpr__', '__setattr__', '__str__', '_associated_classes',
            # '_cached_associated_classes', '_cached_methods', '_cached_properties', '_getAttributeNames', '_get_keys',
            # '_instance_of', '_keys', '_methods', '_properties', 'associated_classes', 'associators', 'derivation',
            #  'id', 'keys', 'methods', 'ole_object', 'path', 'properties', 'property_map', 'put', 'qualifiers',
            #  'references', 'set', 'wmi_property']

            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, class_name)
            dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}

            # s=\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine", ...
            # Name="jsmith" phttp://www.w3.org/1999/02/22-rdf-syntax-ns#type o=Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeProp(class_name)

            try:
                if one_wmi_object.CreationClassName != class_name:
                    logging.warning("CreationClassName=%s" % one_wmi_object.CreationClassName)
            except AttributeError:
                # Maybe this is not a problem at all.
                logging.warning("Class %s does not have CreationClassName" % class_name)
            yield object_path, dict_key_values

    @staticmethod
    def _cleanup_wmi_path(wmi_path):
        """
        This hardcode on class names because backslahes are not easily processed in Sparql queries.
        Therefore, file paths are standardised by replacing backslahes by slashes.
        :param wmi_path:
        :return:
        """
        # HACK: Temporary hard-code !! Same problem as WmiCallbackSelect
        # TODO: We must quadruple backslashes in Sparql queries.
        if "CIM_DataFile.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\").replace("/", "\\")
            logging.debug("wmi_path=%s REPLACED", wmi_path)
        elif "CIM_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\").replace("/", "\\")
            logging.debug("wmi_path=%s REPLACED", wmi_path)
        elif "Win32_Directory.Name" in wmi_path:
            wmi_path = wmi_path.replace("\\\\", "\\").replace("/", "\\")
            logging.debug("wmi_path=%s REPLACED", wmi_path)
        assert wmi_path
        return wmi_path

    def SelectBidirectionalAssociatorsFromObject(self, result_class_name, associator_key_name, wmi_path, role_index):
        """
        This runs an ASSOCIATOR WMI query.
        It then returns an iterator of tuples, these tuples made of an URL and the key-value pairs.

        :param result_class_name: The expected class name of the resulting associated objects.
        :param associator_key_name: The name of the associator between the
        :param wmi_path: The path of the object of which the associated objects are returned,
        :param role_index: Index of the role of the associator. This solution is not entirely general
                           and in some cases the roles are inverted.
        :return: An iterator on url + key-value pairs.
        """

        # 0 if wmi_path is subject, like ASSOCIATOR OF. Otherwise 1.
        assert role_index in [0, 1]

        reference_class_properties = self.associator_keys(associator_key_name)

        # If reference_class_name="CIM_DirectoryContainsFile", then ['GroupComponent', 'PartComponent']
        logging.debug("reference_class_properties=%s" % str(reference_class_properties))
        chosen_role = reference_class_properties[role_index][1]

        return self.select_bidirectional_associators_from_object_generic(
            result_class_name, associator_key_name, wmi_path, chosen_role, wmi_keys_only=False)

    def select_bidirectional_associators_from_object_generic(
            self, result_class_name, associator_key_name, wmi_path, chosen_role, wmi_keys_only):

        wmi_path = self._cleanup_wmi_path(wmi_path)

        # Examples:
        # 'ASSOCIATORS OF {Win32_Process.Handle="1780"} WHERE AssocClass=CIM_ProcessExecutable ResultClass=CIM_DataFile'
        # 'ASSOCIATORS OF {CIM_DataFile.Name="c:\\program files\\mozilla firefox\\firefox.exe"}
        #  WHERE AssocClass = CIM_ProcessExecutable ResultClass = CIM_Process'
        wmi_query = "ASSOCIATORS OF {%s} WHERE AssocClass=%s ResultClass=%s ResultRole=%s" % (
            wmi_path, associator_key_name, result_class_name, chosen_role)
        if wmi_keys_only:
            wmi_query += " KeysOnly"

        logging.debug("WmiCallbackAssociator wmi_query=%s", wmi_query)

        try:
            wmi_objects = self.m_wmi_connection.query(wmi_query)
        except Exception as exc:
            # Probably com_error
            logging.error("WmiCallbackAssociator Caught: %s wmi_query=%s", exc, wmi_query)
            return

        for one_wmi_object in wmi_objects:
            # Path='\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"'
            object_path = str(one_wmi_object.path())
            # logging.debug("WmiCallbackAssociator one_wmi_object.path=%s",object_path)
            list_key_values = WmiKeyValues(self.m_wmi_connection, one_wmi_object, False, result_class_name)
            dict_key_values = {node_key: node_value for node_key, node_value in list_key_values}

            # s=\\MYMACHINE\root\cimv2:Win32_UserAccount.Domain="mymachine",Name="jsmith"
            # p=http://www.w3.org/1999/02/22-rdf-syntax-ns#type
            # o=http://primhillcomputers.com/survol/Win32_UserAccount
            dict_key_values[lib_kbase.PredicateType] = lib_properties.MakeNodeForSparql(result_class_name)

            # logging.debug("WmiCallbackAssociator dict_key_values=%s", dict_key_values)
            yield object_path, dict_key_values

    def associator_keys(self, associator_name):
        """
        This returns the list of roles and classes which define this associator.
        Example:
        "CIM_ProcessExecutable" => [('CIM_DataFile', 'Antecedent'), ('CIM_Process', 'Dependent')])

        :param associator_name: For example "CIM_DirectoryContainsFile"
        :return: For example [('CIM_Directory', 'GroupComponent'), ('CIM_DataFile', 'PartComponent')]

        TODO: This should probably be removed when role indices will not be used, but rather role names.
        """
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

    def enumerate_associated_instances(self, survol_path, associator_name, result_class, result_role):
        """
        For each instance associated to the current one, it returns properties and values,
        for the WMI keys of this class.
        Documentation says:
        "If the KeysOnly keyword is being used in ASSOCIATORS OF and REFERENCES OF queries,
        only the key properties of resulting CIM instances MUST be populated."

        So it reduces the amount of data.
        """
        wmi_path = reformat_path_for_wmi(survol_path)

        iter_objects = self.select_bidirectional_associators_from_object_generic(
            result_class, associator_name, wmi_path, result_role, wmi_keys_only=True)
        for wmi_path, dict_key_values in iter_objects:
            logging.debug("wmi_path=%s", wmi_path)
            yield dict_key_values
