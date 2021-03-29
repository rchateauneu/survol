#!/usr/bin/env python

# INTERMEDIARY RELEASE. TO BE FINISHED.

"""
Python properties
"""

import os
import os.path
import sys

import lib_util
import lib_uris
import lib_common
from lib_properties import pc
from sources_types import python
from sources_types.python import package

try:
    import dis
except ImportError:
    pass

def Usable(entity_type,entity_ids_arr):
    """Can run with Python files only"""

    py_fil_nam = entity_ids_arr[0]

    return False


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    py_fil_nam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    # filNode = lib_uris.gUriGen.FileUri(py_fil_nam)
    # 
    # try:
    # 
    #     AddAssociatedFiles(grph,filNode,py_fil_nam)
    # except:
    #     exc = sys.exc_info()[0]
    #     lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % ( py_fil_nam, str( exc ) ) )
    # AddImportedModules(grph,filNode,py_fil_nam,maxDepth,dispPackages,dispFiles)

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
    Main()
