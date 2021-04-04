#!/usr/bin/env python

"""
WMI namespaces.
"""

import sys
import logging
import lib_util
import lib_common
from lib_properties import pc
try:
    import wmi
except ImportError:
    lib_common.ErrorMessageHtml("Python package WMI is not available")
import lib_wmi

# TODO: Hard-coded list for the moment because we could not find a way
# to list "root" subnamespaces with wmi. Not a problem for the moment.
# http://stackoverflow.com/questions/5332501/how-do-you-query-for-wmi-namespaces
_hardcoded_namespaces = (
    "aspnet",        # Not on Toshiba Win8
    "CIMV2",
    "Cli",           # This does not work on Windows XP
    "Default",
    "directory",
    "Hardware",      # Toshiba Win8
    "HP",            # Not on Toshiba Win8
    "Interop",
    "Microsoft",
    "msdtc",         # Toshiba Win8
    "nap",
    "Policy",        # Not on Toshiba Win8
    "RSOP",
    "SECURITY",      # Not on HP Win7
    "SecurityCenter",
    "SecurityCenter2",
    "ServiceModel",  # Not on Toshiba Win8 nor HP Win7
    "StandardCimv2", # Toshiba Win8
    "subscription",
    "WMI",           # Toshiba Win8 and HP Win7
)


def _sub_namespace(root_node, grph, nskey, cimom_url, ns_depth=1):

    # TODO: VERY PRIMITIVE HARD-CODE TO UNDERSTAND WHY IT RETURNS THE SAME SUB-SUB-NAMESPACES
    # BEYOND LEVEL TWO.
    if ns_depth > 2:
        return

    try:
        conn_wmi = lib_wmi.WmiConnect(cimom_url, nskey, False)
        # With the last flag, it does not throw if it cannot connect.
        if not conn_wmi:
            return
    except wmi.x_wmi as exc:
        logging.warning("WMI: Cannot connect to nskey=%s Caught:%s", nskey, str(exc))
        return

    # If the maximum level is not controlled, it loops endlessly.
    # _sub_namespace cimomUrl=mymachine nskey=aspnet\Security\Security\Security\Security\Security\Security\Security\Security\Security\Secu
    logging.debug("_sub_namespace cimomUrl=%s nskey=%s", cimom_url, nskey)

    wmi_url = lib_wmi.NamespaceUrl("root\\" + nskey, cimom_url)
    wmi_node = lib_common.NodeUrl( wmi_url)

    grph.add((root_node, pc.property_cim_subnamespace, wmi_node))

    try:
        lst_namespaces = conn_wmi.__NAMESPACE()
        logging.debug("lst_namespaces=%s", lst_namespaces)
        # lst_namespaces=[<_wmi_object: \\MYMACHINE\ROOT\cimv2:__NAMESPACE.Name="Security">, <_wmi_object: \\MYMACHINE\ROOT\cimv2:__NAMESPA
        # CE.Name="power">, <_wmi_object: \\MYMACHINE\ROOT\cimv2:__NAMESPACE.Name="ms_409">, <_wmi_object: \\MYMACHINE\ROOT\cimv2:__NAMESP
        # ACE.Name="TerminalServices">, <_wmi_object: \\MYMACHINE\ROOT\cimv2:__NAMESPACE.Name="Applications">]

        for subnamespace in lst_namespaces:
            _sub_namespace(wmi_node, grph, nskey + "\\" + subnamespace.Name, cimom_url, ns_depth + 1)
    except Exception as exc:
        grph.add((wmi_node, pc.property_information, lib_util.NodeLiteral("Caught:%s" % str(exc))))


def Main():
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)

    entity_host = cgiEnv.GetHost()

    logging.debug("entity_host=%s", entity_host)
    entity_host = lib_wmi.NormalHostName(entity_host)

    cimom_url = entity_host

    logging.debug("cimom_url=%s", cimom_url)

    grph = cgiEnv.GetGraph()

    # There is no consensus on the WMI class for namespaces,
    # so we have ours which must be correctly mapped.
    namespace_class = "wmi_namespace"
    # root_node = lib_util.EntityUri(namespace_class,"")
    root_node = lib_util.EntityUri(namespace_class)

    for nskey in _hardcoded_namespaces:
        # _sub_namespace( root_node, grph, nskey )
        try: # "root\\" +
            # _sub_namespace( root_node, grph, nskey, cimom_url )
            _sub_namespace(root_node, grph, nskey, cimom_url)
        except Exception as exc:
            lib_common.ErrorMessageHtml("namespaces_wmi.py cimom_url=%s nskey=%s Caught:%s" % ( cimom_url, nskey , str(exc) ) )

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_cim_subnamespace])
    # cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
