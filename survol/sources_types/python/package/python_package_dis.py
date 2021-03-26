#!/usr/bin/env python

# INTERMEDIARY RELEASE. TO BE FINISHED.

"""
Python properties
"""

import sys
import logging
import importlib

import lib_uris
import lib_common
import lib_util

from sources_types import python as survol_python
from sources_types.python import package as survol_python_package

try:
    import dis
except ImportError:
    pass

#def Usable(entity_type,entity_ids_arr):
#    """Can run with Python files only"""
#
#    packageNam = entity_ids_arr[0]
#
#    return False


def Main():
    paramkey_max_depth = "Maximum depth"
    paramkey_disp_packages = "Display packages"
    paramkey_disp_files = "Display files"

    cgiEnv = lib_common.ScriptEnvironment(
            {paramkey_max_depth: 1, paramkey_disp_packages: True, paramkey_disp_files: False})

    package_nam = cgiEnv.GetId()

    max_depth = cgiEnv.get_parameters(paramkey_max_depth)
    disp_packages= cgiEnv.get_parameters(paramkey_disp_packages)
    disp_files = cgiEnv.get_parameters(paramkey_disp_files)

    package_node = survol_python_package.MakeUri(package_nam)

    logging.debug("package_nam=%s", package_nam)

    grph = cgiEnv.GetGraph()

    tmp_py_fil = lib_util.TmpFile("py_package_deps", "py")
    tmp_py_fil_name = tmp_py_fil.Name

    # This creates a temporary file which imports the package.
    tmp_fd = open(tmp_py_fil_name, "w")
    tmp_fd.write("import %s\n" % package_nam)
    tmp_fd.close()

    survol_python_package.AddImportedModules(grph, package_node, tmp_py_fil_name, max_depth, disp_packages, disp_files)

    try:
        the_module = importlib.import_module(package_nam)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Package:%s Unexpected error:%s" % (package_nam, str(exc)))

    try:
        init_fil_nam = the_module.__file__
        fil_node = lib_uris.gUriGen.FileUri(init_fil_nam)
        grph.add((package_node, survol_python_package.propPythonPackage, fil_node))

        try:
            survol_python.AddAssociatedFiles(grph,fil_node, init_fil_nam)
        except Exception as exc:
            lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % (init_fil_nam, str(exc)))
    except AttributeError:
        pass

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()
