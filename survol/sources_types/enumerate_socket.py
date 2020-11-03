#!/usr/bin/env python

"""
System-wide sockets
"""

import sys
import psutil
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import addr as survol_addr

from lib_properties import pc


def Main():
    paramkey_show_unconnected = "Show unconnected sockets"

    # TODO: At the moment, only uses false default values for boolean parameters,
    # TODO: because CGI and the CGI lib do not send empty strings.
    cgiEnv = lib_common.CgiEnv(
        parameters = {paramkey_show_unconnected: False}
    )

    flag_show_unconnected = bool(cgiEnv.get_parameters(paramkey_show_unconnected))

    grph = cgiEnv.GetGraph()

    for proc in psutil.process_iter():
        try:
            if lib_common.is_useless_process(proc):
                continue

            pid = proc.pid

            # TCP sockets only.
            all_connect = CIM_Process.PsutilProcConnections(proc)
            if all_connect:
                node_process = lib_common.gUriGen.PidUri(pid)

                # Not sure this is the best plmace to add this edge.
                grph.add((node_process, pc.property_host, lib_common.nodeMachine))
                grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

                # TODO: MAYBE CREATES ALL THE PROCESSES AND RUN THE THREADS ON THE COMPLETE LIST ???
                survol_addr.PsutilAddSocketToGraphAsync(node_process,all_connect,grph,flag_show_unconnected)

        except Exception as exc:
            # This is for psutil.AccessDenied and psutil.NoSuchProcess but we do not want to import the module
            exc_str = str(exc)
            if (exc_str.find("AccessDenied") < 0) and (exc_str.find("NoSuchProcess") < 0):
                lib_common.ErrorMessageHtml("Caught:" + exc_str )
                raise

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
