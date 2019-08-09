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
print("path=",sys.path)
print("getcwd=",os.path.getcwd())

import dockit

# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"


class DockitTest(unittest.TestCase):
    """
    Test the execution of the Dockit script.
    """

    def test_file_strace_txt(self):
        dockit.UnitTest(
            inputLogFile = "sample_shell.strace.log",
            tracer = "strace",
            topPid = 0,
            baseOutName = "result_strace",
            outputFormat = "TXT",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "TXT",
            withWarning = False,
            withDockerfile = True,
            updateServer = None)

        fil_txt = open("result_strace.txt")
        fil_txt.close()

        fil_summary = open("result_strace.summary.txt")
        fil_summary.close()

    def test_file_strace_csv(self):
        dockit.UnitTest(
            inputLogFile = "sample_shell.strace.log",
            tracer = "strace",
            topPid = 0,
            baseOutName = "result_strace",
            outputFormat = "CSV",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "XML",
            withWarning = False,
            withDockerfile = False,
            updateServer = None)

        fil_csv = open("result_strace.csv")
        fil_csv.close()

        fil_summary = open("result_strace.summary.txt")
        fil_summary.close()

        fil_docker = open("result_strace.docker/Dockerfile")
        fil_docker.close()

    def test_file_strace_json(self):
        import dockit

        dockit.UnitTest(
            inputLogFile = "sample_shell.strace.log",
            tracer = "strace",
            topPid = 0,
            baseOutName = "result_strace",
            outputFormat = "JSON",
            verbose = True,
            mapParamsSummary = ["CIM_Process","CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat = "TXT",
            withWarning = False,
            withDockerfile = False,
            updateServer = None)

        fil_json = open("result_strace.json")
        data = json.load(fil_json)
        fil_json.close()

        fil_summary = open("result_strace.summary.txt")
        fil_summary.close()


    def test_file_ltrace(self):
        dockit.UnitTest(
            inputLogFile="sample_shell.ltrace.log",
            tracer="ltrace",
            topPid=0,
            baseOutName="result_ltrace",
            outputFormat="JSON",
            verbose=True,
            mapParamsSummary=["CIM_Process", "CIM_DataFile.Category=['Others','Shared libraries']"],
            summaryFormat="TXT",
            withWarning=False,
            withDockerfile=True,
            updateServer=None)

        fil_json = open("result_ltrace.json")
        data = json.load(fil_json)
        fil_json.close()

        fil_summary = open("result_ltrace.summary.txt")
        fil_summary.close()

        fil_docker = open("result_ltrace.docker/Dockerfile")
        fil_docker.close()


if __name__ == '__main__':
    unittest.main()



