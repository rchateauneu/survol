#!/usr/bin/env python

"""
WBEM namespaces
"""

import sys
import lib_util
import lib_wbem
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.CgiEnv(can_process_remote=True)

    cimom_url = cgiEnv.GetHost()

    grph = cgiEnv.GetGraph()

    # There is no consensus on the WBEM class for namespaces,
    # so we have ours which must be correctly mapped.
    namespace_class = "wbem_namespace"
    root_node = lib_util.EntityUri(namespace_class, "")

    try:
        conn_wbem = lib_wbem.WbemConnection(cimom_url)
        nsd = lib_wbem.EnumNamespacesCapabilities(conn_wbem)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Namespaces from :" + cimom_url+" Caught:" + str(exc))

    # TODO: We should draw a namespaces tree but more examples needed.
    for nskey in nsd:

        cnt = nsd[nskey]
        wbem_url = lib_wbem.NamespaceUrl(nskey, cimom_url)
        wbem_node = lib_common.NodeUrl(wbem_url)

        grph.add((root_node, pc.property_cim_subnamespace, wbem_node))
        grph.add((wbem_node, pc.property_information, lib_util.NodeLiteral(nskey)))
        grph.add((wbem_node, pc.property_information, lib_util.NodeLiteral(cnt)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()
