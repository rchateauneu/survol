#!/usr/bin/env python

"""
Monitor system calls with dockit.
"""

import os
import sys
import lib_util
import lib_common
from lib_properties import pc

if False:
    # TODO: Make this cleaner.
    # FIXME: This does not work yet because scripts/cim_objects_definitions.py needs survol/lib_event.py
    # FIXME: ... which cannot be imported due to path issues.

    if ".." not in sys.path:
        sys.path.append("..")

    from scripts import dockit
else:
    dockit = None


def Snapshot():
    cgiEnv = lib_common.CgiEnv()
    process_id = cgiEnv.GetId()

    # This just returns one triple.
    grph = cgiEnv.GetGraph()
    process_node = lib_common.gUriGen.PidUri(process_id)
    grph.add((process_node, pc.property_pid, lib_util.NodeLiteral(process_id)))

    cgiEnv.OutCgiRdf()


# FIXME: Must finish this.
if dockit:
    dockit_dirname = lib_util.standardized_file_path(os.path.dirname(dockit.__file__))


def SendEvents():
    """This is called in a subprocess."""


    # FIXME:
    if not dockit:
        return


    cgiEnv = lib_common.CgiEnv()
    process_id = cgiEnv.GetId()

    # This is called by dockit with one of event to be inserted in the global events graph.
    def dockit_events_callback(rdf_triple):
        grph = cgiEnv.ReinitGraph()
        grph.add(rdf_triple)
        cgiEnv.OutCgiRdf()

    class DockitParameters:
        """
        We want to monitor all system calls of the target process.
        This class and its static values passed all parameters of the procvess to the module "dockit"
        which monitors the calls by attaching to the process given its pid.
        """
        verbose = 1
        with_warning = 1
        map_params_summary = dockit.full_map_params_summary
        with_dockerfile = True
        input_process_id = int(process_id)
        command_line = []
        output_format = "TXT"
        summary_format = None
        input_log_file = None
        output_files_prefix = "dockit_output"
        tracer = dockit.default_tracer(input_log_file, None)
        G_UpdateServer = dockit_events_callback
        aggregator = None
        duplicate_input_log = False
        output_makefile = None

    dockit.start_processing(DockitParameters)


def Main():
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        SendEvents()


if __name__ == '__main__':
    Main()
