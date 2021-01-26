#!/usr/bin/env python

"""
Directory stat information
"""

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import logging
from sources_types import CIM_DataFile
import lib_util
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.CgiEnv()
    fil_nam = cgiEnv.GetId()
    fil_nam = lib_util.standardized_file_path(fil_nam)

    fil_node = lib_common.gUriGen.DirectoryUri(fil_nam)

    grph = cgiEnv.GetGraph()

    info = CIM_DataFile.GetInfoStat(fil_nam)

    # st_mode: protection bits.
    # st_ino: inode number.

    # st_dev: device.
    CIM_DataFile.AddDevice(grph,fil_node,info)

    CIM_DataFile.AddStatNode(grph, fil_node, info)
    CIM_DataFile.AddMagic(grph, fil_node, fil_nam)

    # st_nlink: number of hard links.

    CIM_DataFile.AffFileOwner(grph, fil_node, fil_nam)

    # Displays the file and the parent directories/
    curr_fil_nam = fil_nam
    curr_node = fil_node
    while True:
        dir_path = os.path.dirname(curr_fil_nam)
        if dir_path == curr_fil_nam:
            break
        if dir_path == "":
            break
        dir_node = lib_common.gUriGen.DirectoryUri(dir_path)
        grph.add((dir_node, pc.property_directory, curr_node))
        logging.debug("dir_path=%s", dir_path)
        stat_path = os.stat(dir_path)
        CIM_DataFile.AddStatNode(grph, dir_node, stat_path)

        CIM_DataFile.AddFileProperties(grph, curr_node, curr_fil_nam)

        curr_fil_nam = dir_path
        curr_node = dir_node

    # If windows, print more information: DLL version etc...
    # http://stackoverflow.com/questions/580924/python-windows-file-version-attribute

    # cgiEnv.OutCgiRdf()
    cgiEnv.OutCgiRdf("LAYOUT_TWOPI")


if __name__ == '__main__':
    Main()
