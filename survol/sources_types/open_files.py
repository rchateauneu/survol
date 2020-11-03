#!/usr/bin/env python

"""
System-wide open files
"""

import sys
import psutil
import lib_util
import lib_common
from sources_types import CIM_Process
from lib_properties import pc


def _path_to_nod(path):
    try:
        return Main.dictPathToNod[path]
    except KeyError:
        filNod = lib_common.gUriGen.FileUri( path )
        Main.dictPathToNod[path] = filNod
        return filNod


def _add_pid_file_link(grph, node_process, path):
    """Avoids storing files which are accessed by one process only."""

    # TODO: Resolve symbolic links. Do not do that if shared memory.
    # TODO: AVOIDS THESE TESTS FOR SHARED MEMORY !!!!

    # This because we want to show only the files which are accessed by
    # several processes, otherwise this is too hungry.
    if path in _add_pid_file_link.dictFiles:
        file_node = _path_to_nod(path)

        # Creates also a node for the first process.
        previous_process_node = _add_pid_file_link.dictFiles[path]
        if previous_process_node != "Done":
            grph.add((previous_process_node, pc.property_open_file, file_node))
            # Can use the path as a key as it runs on the current node only.
            _add_pid_file_link.dictFiles[path] = "Done"
        grph.add( ( node_process, pc.property_open_file, file_node ) )
    else:
        # Just store the node. Will see later if accessed by more than two process.
        _add_pid_file_link.dictFiles[path] = node_process


def Main():
    paramkey_show_shared_lib = "Show shared libraries"
    paramkey_show_font_files = "Show font files"
    paramkey_show_non_shared = "Show non shared files"

    # TODO: At the moment, only uses false default values for boolean parameters,
    # TODO: because CGI and the CGI lib do not send empty strings.
    cgiEnv = lib_common.CgiEnv(
        parameters = {paramkey_show_shared_lib: False,
                      paramkey_show_font_files: False,
                      paramkey_show_non_shared: False}
    )

    flag_show_shared_lib = bool(cgiEnv.get_parameters(paramkey_show_shared_lib))
    flag_show_font_files = bool(cgiEnv.get_parameters(paramkey_show_font_files))
    flag_show_non_shared = bool(cgiEnv.get_parameters(paramkey_show_non_shared))

    grph = cgiEnv.GetGraph()

    Main.dictPathToNod = {}

    _add_pid_file_link.dictFiles = {}

    # Maybe this is done in another CGI. What happens when merging ?
    grph.add((lib_common.nodeMachine, pc.property_hostname, lib_util.NodeLiteral(lib_util.currentHostname)))

    for proc in psutil.process_iter():
        try:
            if lib_common.is_useless_process(proc):
                continue

            pid = proc.pid

            node_process = None

            # http://code.google.com/p/psutil/issues/detail?id=340
            # https://github.com/giampaolo/psutil/issues/340
            for fil in proc.open_files():

                # Some files are not interesting even if accessed by many processes.
                if lib_common.is_meaningless_file(fil.path, not flag_show_shared_lib, not flag_show_font_files):
                    continue

                # Adds the process node only if it has at least one open file.
                if node_process == None:
                    node_process = lib_common.gUriGen.PidUri(pid)
                    grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

                # TODO: What about files on a shared drive?
                if flag_show_non_shared:
                    file_node = _path_to_nod(fil.path)
                    grph.add((node_process, pc.property_open_file, file_node))
                else:
                    # This takes into account only files accessed by several processes.
                    _add_pid_file_link(grph, node_process, fil.path)

        except Exception as exc:
            WARNING("Exception:%s", str(exc))
            pass

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")
    # cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


