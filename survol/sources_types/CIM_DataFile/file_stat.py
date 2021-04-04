#!/usr/bin/env python

"""
File stat information

This returns general information about a non-directory data file.
"""

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import logging

import lib_uris
from sources_types import CIM_DataFile
import lib_common
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    file_name = cgiEnv.GetId()

    logging.debug("file_name=%s", file_name)

    file_node = lib_uris.gUriGen.FileUri(file_name)

    grph = cgiEnv.GetGraph()

    info = CIM_DataFile.GetInfoStat(file_name)

    # st_mode: protection bits.
    # st_ino: inode number.

    # st_dev: device.
    CIM_DataFile.AddDevice(grph, file_node, info)

    CIM_DataFile.AddStatNode(grph, file_node, info)
    CIM_DataFile.AddMagic(grph, file_node, file_name)

    # st_nlink: number of hard links.

    CIM_DataFile.AffFileOwner(grph, file_node, file_name)

    # Displays the file and the parent directories.
    current_file_name = file_name
    current_node = file_node
    while True:
        dir_path = os.path.dirname(current_file_name)
        if dir_path == current_file_name:
            break
        if dir_path == "":
            break
        dir_node = lib_uris.gUriGen.DirectoryUri(dir_path)
        grph.add((dir_node, pc.property_directory, current_node))
        logging.debug("file_stat.py dir_path=%s", dir_path)
        stat_path = os.stat(dir_path)
        CIM_DataFile.AddStatNode(grph, dir_node, stat_path)

        CIM_DataFile.AddFileProperties(grph, current_node, current_file_name)

        current_file_name = dir_path
        current_node = dir_node

    # If windows, print more information: DLL version etc...
    # http://stackoverflow.com/questions/580924/python-windows-file-version-attribute

    cgiEnv.OutCgiRdf("LAYOUT_RECT_RL")


if __name__ == '__main__':
    Main()
