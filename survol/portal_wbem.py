#!/usr/bin/env python

"""
WBEM portal
"""

import sys
import logging
import lib_common

try:
    import lib_wbem
except ImportError:
    lib_common.ErrorMessageHtml("WBEM not available")
from lib_properties import pc


def Main():
    """This can process remote hosts because it does not call any script, just shows them."""
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    name_space, entity_type = cgiEnv.get_namespace_type()

    entity_host = cgiEnv.GetHost()
    host_id = cgiEnv.GetId()
    logging.debug("entity_host=%s entity_type=%s hostname=%s", entity_host, entity_type, host_id)

    wbem_urls_list = lib_wbem.GetWbemUrlsTyped(entity_host, name_space, entity_type, host_id)

    # Maybe some of these servers are not able to display anything about this object.
    for url_wbem, wbem_host in wbem_urls_list:
        logging.debug("url_wbem=%s wbem_host=%s", url_wbem, wbem_host)
        wbem_node = lib_common.NodeUrl(url_wbem)
        host_node = lib_common.gUriGen.HostnameUri(wbem_host)
        grph.add((host_node, pc.property_information, wbem_node))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
