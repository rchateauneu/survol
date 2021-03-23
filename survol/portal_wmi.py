#!/usr/bin/env python

"""
WMI portal
"""

import lib_uris
import lib_wmi
import lib_common
from lib_properties import pc


def Main():
    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)

    grph = cgiEnv.GetGraph()

    entity_host = cgiEnv.GetHost()
    entity_host = lib_wmi.NormalHostName(entity_host)


    # TODO: We may also loop on all machines which may describe this object.
    wmiurl = lib_wmi.GetWmiUrl(entity_host, "", "", "")
    if not wmiurl is None:
        wmi_node = lib_common.NodeUrl(wmiurl)

        host_node = lib_uris.gUriGen.HostnameUri(entity_host)
        grph.add((host_node, pc.property_information, wmi_node))
    else:
        lib_common.ErrorMessageHtml("WMI module not installed")

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
