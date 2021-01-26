#!/usr/bin/env python

"""
Monitor system calls with dockit.
"""

import os
import sys
import atexit
import logging
import traceback

import lib_util
import lib_common
from lib_properties import pc

os.environ["PYTHONUNBUFFERED"] = "1"

if True:
    # TODO: Make this cleaner.
    # FIXME: This does not work yet because scripts/cim_objects_definitions.py needs survol/lib_event.py
    # FIXME: ... which cannot be imported due to path issues.

    if ".." not in sys.path:
        sys.path.append("..")
    if "../.." not in sys.path:
        sys.path.append("../..")

    try:
        from scripts import dockit
    except Exception as exc:
        sys.stderr.write("exc=%s\n" % exc)
        sys.stderr.flush()
        raise
else:
    dockit = None


def Snapshot():
    logging.getLogger().setLevel(logging.DEBUG)
    sys.stderr.write("Snapshot File=" + __file__ + "\n")
    logging.info("Snapshot mode")

    cgiEnv = lib_common.CgiEnv()
    process_id = cgiEnv.GetId()

    logging.debug("Snapshot process_id=%s" % process_id)

    # This just returns one triple.
    grph = cgiEnv.GetGraph()
    process_node = lib_common.gUriGen.PidUri(process_id)
    grph.add((process_node, pc.property_pid, lib_util.NodeLiteral(process_id)))

    cgiEnv.OutCgiRdf()


# FIXME: Must finish this.
if dockit:
    dockit_dirname = lib_util.standardized_file_path(os.path.dirname(dockit.__file__))
    sys.stderr.write("File=" + __file__ + " dockit_dirname=" + dockit_dirname + "\n")


def _atexit_handler_detach(process_id):
    """This is called when this CGI script leaves for any reason.
    Its purpose is to detach from the target process."""
    sys.stderr.write("_atexit_handler process_id=%d\n" % process_id)


def SendEvents():
    """This is called in a subprocess started by the Python module supervisor."""

    logging.info("SendEvents")

    sys.stderr.write("SendEvent events\n")

    # FIXME:
    if not dockit:
        logging.error("dockit not available")
        sys.stderr.write("File=" + __file__ + " dockit not loaded" + "\n")
        return

    logging.info("dockit available")
    cgiEnv = lib_common.CgiEnv()
    process_id = cgiEnv.GetId()
    logging.info("process_id=%s" % process_id)
    sys.stderr.write("SendEvents process_id=%s\n" % process_id)

    atexit.register(_atexit_handler_detach, process_id)
    logging.info("atexit handler set")

    # This is called by dockit with one of event to be inserted in the global events graph.
    def dockit_events_callback(rdf_triple):
        grph = cgiEnv.ReinitGraph()
        logging.info("dockit_events_callback")
        sys.stderr.write("dockit_events_callback rdf_triple=%s\n" % rdf_triple)
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

    sys.stderr.write("SendEvents process_id=%s DockitParameters (s) reated\n" % process_id)

    # TODO: How to release the target process when this leaves ?

    try:
        dockit.start_processing(DockitParameters)
    except Exception as exc:
        logging.error("SendEvents caught (stderr): %s\n" % exc)
        sys.stderr.write("SendEvents caught (stderr): %s\n" % exc)

    sys.stderr.write("SendEvents after processing\n")


def Main():
    # Temporary setting of logging level to the max.
    logging.getLogger().setLevel(logging.DEBUG)
    if lib_util.is_snapshot_behaviour():
        logging.debug("system calls snapshot")
        Snapshot()
    else:
        logging.debug("system calls events")
        try:
            SendEvents()
        except Exception as err:
            sys.stderr.write("Caught:%s\n" % err)
            logging.error("Caught:%s" % err)
            raise


if __name__ == '__main__':
    Main()
