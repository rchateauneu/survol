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
# This is needed when running from PyCharm.
sys.path.insert(0,"../survol/scripts")

# On Travis, getcwd= /home/travis/build/rchateauneu/survol
# path= ['../survol/scripts', '/home/travis/build/rchateauneu/survol',
# '../survol', '/home/travis/build/rchateauneu/survol', '/home/travis/virtualenv/python2.7.15/bin',
# '/home/travis/virtualenv/python2.7.15/lib/python27.zip', '/home/travis/virtualenv/python2.7.15/lib/python2.7',
# '/home/travis/virtualenv/python2.7.15/lib/python2.7/plat-linux2',
# '/home/travis/virtualenv/python2.7.15/lib/python2.7/lib-tk',
# '/home/travis/virtualenv/python2.7.15/lib/python2.7/lib-old', '/home/travis/virtualenv/python2.7.15/lib/python2.7/lib-dynload',
# '/opt/python/2.7.15/lib/python2.7', '/opt/python/2.7.15/lib/python2.7/plat-linux2',
# '/opt/python/2.7.15/lib/python2.7/lib-tk', '/home/travis/virtualenv/python2.7.15/lib/python2.7/site-packages',
# 'survol', '/home/travis/build/rchateauneu/survol/survol']
sys.path.insert(0,"survol/scripts")

print("path=",sys.path)
print("getcwd=",os.getcwd())

import dockit

# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"

# Travis and PyCharm do not start this unit tests script from the same directory.
# The test files are alongside the script.
input_test_files_dir = os.path.dirname(__file__)

class DockitTest(unittest.TestCase):
    """
    Test the execution of the Dockit script.
    """

    def test_file_strace_txt(self):
        dockit.UnitTest(
            inputLogFile = os.path.join(input_test_files_dir, "sample_shell.strace.log"),
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
            inputLogFile = os.path.join(input_test_files_dir, "sample_shell.strace.log"),
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
            inputLogFile = os.path.join(input_test_files_dir, "sample_shell.strace.log"),
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
            inputLogFile = os.path.join(input_test_files_dir, "sample_shell.ltrace.log"),
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



