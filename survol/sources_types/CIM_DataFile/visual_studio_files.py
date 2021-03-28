#!/usr/bin/env python

"""
Visual studio files.
"""

# .sln, .vcxproj and .proj

import os
import os.path
import sys

import lib_uris
import lib_util
import lib_common
from lib_properties import pc


def Usable(entity_type, entity_ids_arr):
    """Can run with Visual Studio files only"""

    fil_nam = entity_ids_arr[0]

    fil_ext = os.path.splitext(fil_nam)[1]
    return fil_ext.lower() in _visual_studio_extensions


def _add_msvc_vcxproj(grph, node, fil_nam):
    """This displays information about a *.vcxproj file"""


def _add_msvc_sln(grph, node, fil_nam):
    """This displays information about a *.sln MSVC solution file"""


def _add_msvc_proj(grph, node, fil_nam):
    """This displays information about a *.proj msbuild file"""


_visual_studio_extensions = {
    ".vcxproj": _add_msvc_vcxproj,
    ".sln": _add_msvc_sln,
    ".proj": _add_msvc_proj}


def _add_java_associated_files(grph, node, fil_nam):
    filename_no_ext, file_extension = os.path.splitext(fil_nam)
    _visual_studio_extensions[file_extension](grph, node, fil_nam)


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    java_fil_nam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    fil_node = lib_uris.gUriGen.FileUri(java_fil_nam)

    try:
        _add_java_associated_files(grph, fil_node, java_fil_nam)
    except Exception as exc:
        lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % (java_fil_nam, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()

# https://en.wikipedia.org/wiki/Java_class_file
# Class files are identified by the following 4 byte header (in hexadecimal): CA FE BA BE (the first 4 entries in the table below).