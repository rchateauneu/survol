#!/usr/bin/env python

"""
Monitor system calls with dockit.
"""

import os
import sys
import lib_util
import lib_common
from survol.scripts import dockit

def MainSnapshot():
    cgiEnv = lib_common.CgiEnv()
    process_id = cgiEnv.GetId()
    cgiEnv.OutCgiRdf()


dockit_dirname = lib_util.standardized_file_path(os.path.dirname(dockit.__file__))



# This is called in a subprocess.
def MainDockit():
    cgiEnv = lib_common.CgiEnv()
    process_id = cgiEnv.GetId()

    # This is called by dockit with one of event to be inserted in the global events graph.
    def dockit_events_callback(rdf_triple):
        grph = cgiEnv.ReinitGraph()
        grph.add(rdf_triple)
        cgiEnv.OutCgiRdf()


    class dockit_parameters:
        verbose = 1
        with_warning = 1
        map_params_summary = dockit.full_map_params_summary
        with_dockerfile = True
        input_process_id = int(process_id)
        output_format = "TXT"
        summary_format = None
        input_log_file = None
        output_files_prefix = "dockit_output"
        tracer = dockit.default_tracer(input_log_file, None)
        G_UpdateServer = dockit_events_callback
        aggregator = None
        duplicate_input_log = False

    dockit._start_processing(dockit_parameters)


    # cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        MainSnapshot()
    else:
        MainDockit()
