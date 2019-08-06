#!/usr/bin/python

from __future__ import print_function

import cgitb
import cgi
import os
import sys
import json
import socket
import unittest

# This loads the module from the source, so no need to install it, and no need of virtualenv.
sys.path.insert(0,"../survol/scripts")

# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"


class DockitTest(unittest.TestCase):
    """
    Test the execution of the Dockit script.
    """

    def test_file_strace(self):
        import dockit

        dockit.UnitTest(
            inputLogFile = "sample_shell.strace.log",
            tracer = "strace",
            topPid = 0,
            outFile = "result_strace.txt",
            outputFormat = "JSON",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "TXT",
            withWarning = False,
            withDockerfile = True,
            updateServer = None)


    def test_file_ltrace(self):
        import dockit

        dockit.UnitTest(
            inputLogFile="sample_shell.ltrace.log",
            tracer="ltrace",
            topPid=0,
            outFile="result_ltrace.txt",
            outputFormat="JSON",
            verbose=True,
            mapParamsSummary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat="TXT",
            withWarning=False,
            withDockerfile=True,
            updateServer=None)


if __name__ == '__main__':
    unittest.main()



