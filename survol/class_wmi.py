#!/usr/bin/env python

"""
WMI class portal
"""

import sys
import cgi
import urllib
import logging
import lib_util
import lib_common
import lib_wmi
from lib_properties import pc


def _add_extra_nodes(grph, root_node):
    """Adds an extra nodes to make things more interesting."""
    objtype_node = lib_common.NodeUrl(lib_util.uriRoot + '/objtypes.py')
    grph.add((root_node, pc.property_rdf_data_nolist2, objtype_node))
    # TODO: Add link to https://docs.microsoft.com/en-us/windows/desktop/cimwin32prov/win32-service


def Main():
    paramkey_enum_instances = "Enumerate instances"

    cgiEnv = lib_common.ScriptEnvironment(parameters={paramkey_enum_instances: False})

    flag_enum_instances = bool(cgiEnv.get_parameters(paramkey_enum_instances))

    grph = cgiEnv.GetGraph()

    name_space, class_name = cgiEnv.get_namespace_type()
    logging.info("name_space=%s class_name=%s", name_space, class_name)

    # If name_space is not provided, it is set to "root/CIMV2" by default.
    if not class_name:
        lib_common.ErrorMessageHtml("Class name should not be empty")

    cimom_url = cgiEnv.GetHost()

    root_node = lib_util.EntityClassNode(class_name, name_space, cimom_url, "WMI")

    _add_extra_nodes(grph, root_node)

    # Not sure why, but sometimes backslash replaced by slash, depending where we come from ?
    name_space = name_space.replace("/", "\\")

    try:
        conn_wmi = lib_wmi.WmiConnect(cimom_url, name_space)
    except Exception as exc:
        lib_common.ErrorMessageHtml("WMI Connecting to cimom_url=%s name_space=%s Caught:%s\n"
                                    % (cimom_url, name_space, str(exc)))

    # http://rchateau-hp:8000/survol/class_wmi.py?xid=\\rchateau-HP\root\CIMV2%3ACIM_Directory.
    # http://rchateau-hp:8000/survol/class_wmi.py?xid=\rchateau-HP\root\CIMV2%3ACIM_Directory.&mode=html

    lib_wmi.WmiAddClassQualifiers(grph, conn_wmi, root_node, class_name, True)

    try:
        wmi_class = getattr(conn_wmi, class_name)
    except Exception as exc:
        lib_common.ErrorMessageHtml("class_wmi.py cimom_url=%s name_space=%s class_name=%s Caught:%s\n"
                                    % (cimom_url, name_space, class_name, str(exc)))

    # wmi_class=[Abstract, Locale(1033): ToInstance, UUID("{8502C55F-5FBB-11D2-AAC1-006008C78BC7}"): ToInstance]
    # class CIM_Directory : CIM_LogicalFile
    # {
    # };
    logging.debug("wmi_class=%s", str(wmi_class))

    # Some examples of WMI queries.
    # http://timgolden.me.uk/python/wmi/tutorial.html
    #
    # logical_disk = wmi.WMI(moniker="//./root/cimv2:Win32_LogicalDisk")
    # c_drive = wmi.WMI(moniker='//./root/cimv2:Win32_LogicalDisk.DeviceID="C:"')
    # c = wmi.WMI("MachineB", user=r"MachineB\fred", password="secret")
    #
    # A WMI class can be "called" with simple equal-to parameters to narrow down the list.
    # This filtering is happening at the WMI level.
    # for disk in c.Win32_LogicalDisk(DriveType=3):
    # for service in c.Win32_Service(Name="seclogon"):
    #
    # Arbitrary WQL queries can be run, but apparently WQL selects first all elements from WMI,
    # then only does its filtering:
    # for disk in wmi.WMI().query("SELECT Caption, Description FROM Win32_LogicalDisk WHERE DriveType <> 3"):
    #
    if flag_enum_instances:
        # Biggest difficulty is the impossibility to limit the numbers of results fetched by WMI.
        # Many classes have to many elements to display them.
        # This makes it virtually impossible to select their elements.
        if lib_wmi.WmiTooManyInstances(class_name):
            lib_common.ErrorMessageHtml("Too many elements in class_name=%s\n" % class_name)

        try:
            lst_obj = wmi_class()
        except Exception as exc:
            lib_common.ErrorMessageHtml("Caught when getting list of %s\n" % class_name)

        num_lst_obj = len(lst_obj)
        logging.debug("class_name=%s type(wmi_class)=%s len=%d", class_name, str(type(wmi_class)), num_lst_obj)

        if num_lst_obj == 0:
            grph.add((root_node, pc.property_information, lib_util.NodeLiteral("No instances in this class")))

        for wmi_obj in lst_obj:
            # Full natural path: We must try to merge it with WBEM Uris.
            # '\\\\RCHATEAU-HP\\root\\cimv2:Win32_Process.Handle="0"'
            # https://jdd:test@acme.com:5959/cimv2:Win32_SoftwareFeature.Name="Havana",ProductName="Havana",Version="1.0"

            try:
                full_pth = str(wmi_obj.path())
            except UnicodeEncodeError as exc:
                # UnicodeEncodeError: 'ascii' codec can't encode characters in position 104-108: ordinal not in range(128)
                logging.warning("Exception %s", str(exc))
                continue

            # sys.stderr.write("full_pth=%s\n" % full_pth)

            if full_pth == "":
                logging.warning("Empty path wmi_obj=%s", str(wmi_obj))
                # The class Win32_PnPSignedDriver (Maybe others) generates dozens of these messages.
                # This is not really an issue as this class should be hidden from applications.
                # logging.warning Empty path wmi_obj=
                # instance of Win32_PnPSignedDriver
                # {
                #         ClassGuid = NULL;
                #         CompatID = NULL;
                #         Description = NULL;
                #         DeviceClass = "LEGACYDRIVER";
                #         DeviceID = "ROOT\\LEGACY_LSI_FC\\0000";
                #         DeviceName = "LSI_FC";
                #         DevLoader = NULL;
                #         DriverName = NULL;
                #         DriverProviderName = NULL;
                #         DriverVersion = NULL;
                #         FriendlyName = NULL;
                #         HardWareID = NULL;
                #         InfName = NULL;
                #         Location = NULL;
                #         Manufacturer = NULL;
                #         PDO = NULL;
                # };
                continue

            # full_pth=\\RCHATEAU-HP\root\CIMV2:Win32_SoundDevice.DeviceID="HDAUDIO\\FUNC_01&VEN_10EC&DEV_0221&SUBSYS_103C18E9&REV_1000\\4&3BC582&0&0001"
            full_pth = full_pth.replace("&", "&amp;")
            wmi_instance_url = lib_util.EntityUrlFromMoniker(full_pth)
            logging.debug("wmi_instance_url=%s", wmi_instance_url)

            wmi_instance_node = lib_common.NodeUrl(wmi_instance_url)

            grph.add((root_node, pc.property_class_instance, wmi_instance_node))

    # TODO: On pourrait rassembler par classes, et aussi afficher les liens d'heritages des classes.

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_class_instance])

    # TODO: Prev/Next like class_wbem.py


if __name__ == '__main__':
    Main()
