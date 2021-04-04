#!/usr/bin/env python

"""
Merge data from several sources
"""

import os
import sys
import time
import cgi
import logging
import lib_util
import lib_common


# This is called as a CGI script, and its parameters are input URLs in Base64UrlSafe format.
# It merges the input urls into a single RDF document,
# then transformed into DOT, then SVG by Graphviz, then displayed.
def Main():
    orig_req_uri = lib_util.RequestUri()

    # It initialises an implicit global object similar.
    # When in the mode of global merging, the method "cgiEnv.OutCgiRdf()" does not generate anything,
    # but simply stores the new cgiEnv in a global list..
    # The script loops on the URLs passed as CGI parameters.
    # The URLs are loaded and their content merged into the container lib_common.globalGraph
    lib_common.CgiEnvMergeMode()

    arguments = cgi.FieldStorage()

    # The display mode is read now, otherwise the CGI arguments are later destroyed, in this script.
    the_mode = lib_util.GuessDisplayMode()
    logging.debug("the_mode=%s", the_mode)

    # Concatenation of error messages of each script.
    cumulated_error = ""

    # This logic might be needed in lib_client.py
    for urlfil in arguments.getlist("url"):
        # The parameters are coded in base64, although we leave the possibility not to encode them,
        # for compatibility with test scripts.

        complete_url = lib_util.Base64Decode(urlfil)

        logging.debug("complete_url=%s", complete_url)

        # Only the URL without the arguments.
        url_split = complete_url.split("?")
        url_no_args = url_split[0]
        if len(url_split) > 1:
            cgi_query_string = url_split[1]
        else:
            cgi_query_string = ""

        # The URL might be absolute or relative. Example:
        # "survol/sources_types/enumerate_CIM_Process.py?xid=."
        idx_htbin = url_no_args.find("sources_types/")
        if idx_htbin == -1:
            # This may be the main presentation page of a Survol, WMI or WBEM object. Example:
            # "http://127.0.0.1:80/Survol/survol/entity.py?xid=CIM_Process.Handle=640"
            survol_prefix = "survol/"
            idx_survol = url_no_args.find(survol_prefix)
            if idx_survol == -1:
                # TODO: This happens if the URL is a main presentation page of an object,
                # instead of a script: Something like "survol/entity.py/entity.py?xid=..."
                # This should be fixed but is not an issue.
                logging.warning("merge: SHOULD NOT HAPPEN url=%s",complete_url)
                url_path_short = "INVALID_MERGED_URL"
            else:
                # Just starts at the beginning of the script name: "entity.py", "entity_wmi.py", "entity_wbem.py".
                url_path_short = url_no_args[idx_survol + len(survol_prefix):]
        else:
            url_path_short = url_no_args[idx_htbin:]

        # url_path_short is the actual script to load.
        url_dir_nam = os.path.dirname(url_path_short)

        # The directory of the script is used to build a Python module name.
        modu_nam = url_dir_nam.replace("/", ".")

        url_fil_nam = os.path.basename(url_path_short)

        logging.debug("url_path_short=%s url_dir_nam=%s modu_nam=%s url_fil_nam=%s",
                      url_path_short, url_dir_nam, modu_nam, url_fil_nam)
        try:
            # argDir="sources_types.win32" urlFileNam="enumerate_top_level_windows.py"
            imported_mod = lib_util.GetScriptModule(modu_nam, url_fil_nam)
        except Exception as exc:
            logging.warning("Caught %s when loading modu_nam=%s url_fil_nam=%s", exc, modu_nam, url_fil_nam)
            continue

        if not imported_mod:
            cumulated_error = "merge_scripts.py Cannot import complete_url=%s" % complete_url
            continue

        try:
            # The entire URL must be "injected" so the parameters will be properly parsed,
            # when Main() call lib_util.RequestUri().
            # The script passed as CGI parameter, believes that it is loaded as a plain URL.
            url_unquote = lib_util.urllib_unquote(complete_url)
            os.environ["REQUEST_URI"] = url_unquote

            os.environ['SCRIPT_NAME'] = url_fil_nam
            # "xid=EURO%5CLONL00111310@process:16580"
            os.environ['QUERY_STRING'] = cgi_query_string

            lib_common.enable_error_message(False)

            # This executes the script: The new nodes and links are merged in a global RDF container.
            imported_mod.Main()
        except Exception as exc:
            logging.warning("Caught %s when executing Main in modu_nam=%s url_fil_nam=%s", exc, modu_nam, url_fil_nam)
            if cumulated_error != "":
                cumulated_error += " ; "
            cumulated_error += " url=" + url_no_args + " / " + url_fil_nam + ":" + str(exc)

            continue
        lib_common.enable_error_message(True)

    os.environ["REQUEST_URI"] = orig_req_uri

    # OutCgiRdf has been called by each script without writing anything,
    # but the specific parameters per script are stored inside.

    # Here, all the RDF nodes and links, loaded from each URL, and then merged in lib_common.globalGraph,
    # are then transformed into the chosen output format.
    lib_common.MergeOutCgiRdf(the_mode, cumulated_error)


if __name__ == '__main__':
    Main()

