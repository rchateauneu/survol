#!/usr/bin/env python

"""
Symbolic link destination (Recursive)
"""

# List of the symbolic links this file point to.
# It checks if qny of the intermediate directories of the file path
# is a symbolic link, and therefore make a recursive walk.

import os
import sys
import lib_common
import lib_symlink
from lib_properties import pc


def Usable(entity_type,entity_ids_arr):
    """File must be a symbolic link"""
    fil_nam = entity_ids_arr[0]
    try:
        lnk_path = os.readlink(fil_nam)
        return True
    except:
        return False


def Main():
    cgiEnv = lib_common.CgiEnv()
    file_path = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    try:
        # This assumes that file_path is absolute.
        lib_symlink.recursive_symlink_analysis(grph, file_path)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:"+str(exc))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
