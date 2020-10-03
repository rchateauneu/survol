#!/usr/bin/env python

"""
Files opened by process
"""

import sys
import lib_common
from sources_types import CIM_Process

from lib_properties import pc


def Main():
    paramkey_show_shared_lib = "Show shared libraries"
    paramkey_show_font_files = "Show font files"

    cgiEnv = lib_common.CgiEnv(
        parameters = { paramkey_show_shared_lib : False,
                       paramkey_show_font_files : False }
    )
    top_pid = int(cgiEnv.GetId())

    flag_show_shared_lib = bool(cgiEnv.get_parameters(paramkey_show_shared_lib))
    flag_show_font_files = bool(cgiEnv.get_parameters(paramkey_show_font_files))

    grph = cgiEnv.GetGraph()

    proc_obj = CIM_Process.PsutilGetProcObj(top_pid)

    # sys.stderr.write("top_pid=%d\n" % top_pid)

    node_process = lib_common.gUriGen.PidUri(top_pid)
    CIM_Process.AddInfo(grph, node_process, [str(top_pid)])

    ################################################################################

    try:
        fillist = proc_obj.open_files()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:"+str(exc)+":"+str(proc_obj))

    for fil in fillist:
        # TODO: Resolve symbolic links. Do not do that if shared memory.
        # TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!
        if lib_common.is_meaningless_file(fil.path, not flag_show_shared_lib, not flag_show_font_files):
            continue

        file_node = lib_common.gUriGen.FileUri(fil.path)
        grph.add((node_process, pc.property_open_file, file_node))

    # This works but not really necessary because there are not so many files.
    # cgiEnv.OutCgiRdf( "", [pc.property_open_file] )
    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
    Main()
