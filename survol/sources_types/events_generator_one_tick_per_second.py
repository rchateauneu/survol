#!/usr/bin/env python

"""
Sends one event per second. Test purpose.
"""

import os
import sys
import time
import datetime
import lib_util
import lib_common
import lib_properties

ParamA = "parama"
ParamB = "paramb"

def Main():
    cgiEnv = lib_common.CgiEnv(parameters={ParamA: 1, ParamB: "Two"})

    # This is to ensure that all CGI parameters are handled.
    parameter_a = int(cgiEnv.get_parameters(ParamA))
    parameter_b = cgiEnv.get_parameters(ParamB)

    grph = cgiEnv.GetGraph()
    timestamp_property = lib_properties.MakeProp("ticker_timestamp")
    param_a_property = lib_properties.MakeProp(ParamA)
    param_b_property = lib_properties.MakeProp(ParamB)
    current_pid = os.getpid()
    node_process = lib_common.gUriGen.PidUri(current_pid)

    datetime_now = datetime.datetime.now()
    timestamp_literal = datetime_now.strftime("%Y-%m-%d %H:%M:%S")
    grph.add((node_process, timestamp_property, lib_common.NodeLiteral(timestamp_literal)))

    grph.add((node_process, param_a_property, lib_common.NodeLiteral(parameter_a)))
    grph.add((node_process, param_b_property, lib_common.NodeLiteral(parameter_b)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        # Or any condition telling that it does not run as a CGI script, like mode == "daemon",
        # or the absence of HTTP environment variables.
        # The looping logic might be different but the ideas are
        # - to use a similar code for a snapshot and for an event loop.
        # - More importantly, write in a plain RDFLIB graph, flushed by OutCgiRdf().
        #   This greatly simplifies the code.
        while True:
            Main()



