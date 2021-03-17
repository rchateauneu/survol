#!/usr/bin/env python

"""
Embedded Windows icon resources
"""

import os
import re
import sys
import time
import lib_mime
import lib_util
import lib_kbase
import lib_win32
import lib_common
from lib_properties import pc
from sources_types import win32
from sources_types.win32 import resource as survol_win32_resource

# This script works only on a Windows executable or DLL etc...
Usable = lib_util.UsableWindowsBinary


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    path_name = cgiEnv.GetId()

    icon_groups = survol_win32_resource.GetIconNamesList(path_name)

    fil_node = lib_common.gUriGen.FileUri(path_name)

    for group_name in icon_groups:
        # TODO: Is it sorted in lib_export_html.py ??
        # When clicking on these links, it typically displays an image.
        lib_mime.AddMimeUrl(grph, fil_node, "win32/resource", survol_win32_resource.mimeTypeResource, [path_name, group_name])

    # This displays a list of images file names.
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_rdf_data_nolist2] )


if __name__ == '__main__':
    Main()

