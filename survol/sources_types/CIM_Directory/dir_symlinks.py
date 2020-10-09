#!/usr/bin/env python

"""
Symbolic link destination (Recursive)
"""

# List of the symbolic links this file point to.
# It checks if qny of the intermediate directories of the file path
# is a symbolic link, and therefore make a recursive walk.

import os
import re
import sys
from sources_types import CIM_DataFile
import lib_common
from lib_properties import pc


def Usable(entity_type, entity_ids_arr):
    """Directory must be a symbolic link"""
    fil_nam = entity_ids_arr[0]
    try:
        lnk_path = os.readlink(fil_nam)
        return True
    except:
        return False


def _recursive_symlink_analysis(grph, beginning, physical, file_split):
    file_depth = len(file_split)

    if file_depth == 0:
        if beginning != physical:
            node_phys = lib_common.gUriGen.FileUri(physical)
            CIM_DataFile.AddInfo(grph, node_phys, [physical])
            node_link = lib_common.gUriGen.FileUri(beginning)
            CIM_DataFile.AddInfo(grph, node_link, [beginning])
            grph.add((node_phys, pc.property_symlink, node_link))
        return

    ext = "/" + file_split[0]
    _recursive_symlink_analysis(grph, beginning + ext, physical + ext, file_split[1:])

    try:
        new_begin = beginning + ext
        lnk_path = os.readlink(new_begin)

        # BEWARE, the link is absolute or relative.
        # It's a bit nonsensical because it depends on the current path.
        if lnk_path[0] == '/':
            full_path = lnk_path
        else:
            full_path = beginning + "/" + lnk_path
        _recursive_symlink_analysis(grph, full_path, physical + ext, file_split[1:])
    except:
        # print("Not a symlink:"+beginning)
        return


def Main():
    cgiEnv = lib_common.CgiEnv()
    file_path = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    try:
        file_split = file_path.split('/')
        # This assumes that file_path is absolute and begins with a slash.
        _recursive_symlink_analysis(grph, "", "", file_split[1:])
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:"+str(exc))

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
