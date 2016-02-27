#!/usr/bin/python

import sys
import rdflib
import lib_util
import lib_common
from lib_properties import pc

try:
    import pyodbc
except ImportError:
    lib_common.ErrorMessageHtml("pyodbc Python library not installed")