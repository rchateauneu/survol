#!/usr/bin/python

"""
Socket content sniffing
"""

import os
import sys
import time
import lib_common
from lib_common import pc

def Main():
	cgiEnv = lib_common.CgiEnv()
	socketNam = cgiEnv.GetId()

	grph = cgiEnv.GetGraph()

	lib_common.ErrorMessageHtml("Not implemented yet")

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
