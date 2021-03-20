#!/usr/bin/env python

"""
Python package dependencies
"""

import os
import sys
import lib_common

from sources_types import python as survol_python
from sources_types.python import package as survol_python_package


def Usable(entity_type, entity_ids_arr):
    """Can run with Python files only"""

    fil_nam = entity_ids_arr[0]

    # But probably it is not enough and we should try to open it.
    fil_ext = os.path.splitext(fil_nam)[1]
    return fil_ext.lower() in survol_python.pyExtensions


def Main():
    paramkey_max_depth = "Maximum depth"
    paramkey_disp_packages = "Display packages"
    paramkey_disp_files = "Display files"

    cgiEnv = lib_common.ScriptEnvironment({
        paramkey_max_depth: 1,
        paramkey_disp_packages: True,
        paramkey_disp_files: False})

    max_depth = cgiEnv.get_parameters(paramkey_max_depth)
    disp_packages= cgiEnv.get_parameters(paramkey_disp_packages)
    disp_files = cgiEnv.get_parameters(paramkey_disp_files)

    py_fil_nam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    fil_node = lib_common.gUriGen.FileUri(py_fil_nam)

    try:
        survol_python.AddAssociatedFiles(grph, fil_node, py_fil_nam)
        survol_python_package.AddImportedModules(grph, fil_node, py_fil_nam, max_depth, disp_packages, disp_files)
    except Exception as exc:
        lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % (py_fil_nam, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
