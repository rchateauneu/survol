#!/usr/bin/env python

"""
Scan process for HTTP urls.
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

SlowScript = True

def Main():
    cgiEnv = lib_common.CgiEnv()
    pidint = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    node_process = lib_common.gUriGen.PidUri(pidint)

    try:
        # http://daringfireball.net/2010/07/improved_regex_for_matching_urls
        rgx_http = r"https?://[a-z_0-9\.]+"

        resu_urls = memory_regex_search.GetRegexMatches(pidint, rgx_http)

        resu_clean = set()

        # The URLs which are detected in the process memory might be broken, invalid etc...
        # Only some of them are in valid strings. The other may come from deallocated memory etc...
        for url_idx in resu_urls:
            url_http = resu_urls[url_idx]
            # In memory, we find strings such as "http://adblockplus.orgzzzzzzzzzzzz"
            # or "http://adblockplus.orgzzzzzzzzzzzz"
            # "activistpost.netzx"

            url_http = url_http.decode()
            split_dots = url_http.split(".")
            top_level = split_dots[-1]
            # Primitive way to remove apparently broken URLs.
            if(len(top_level) > 4):
                continue
            resu_clean.add(url_http)

        for url_http in resu_clean:
            # sys.stderr.write("url_http=%s\n"%url_http)
            node_portal_web = lib_common.NodeUrl(url_http)
            grph.add((node_process, pc.property_rdf_data_nolist1, node_portal_web))

    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:%s. Protection ?" % str(exc))

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()

