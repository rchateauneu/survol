#!/usr/bin/env python

"""
Files in directory
"""

import os
import re
import sys
import logging

import lib_uris
import lib_common
from sources_types import CIM_DataFile
import lib_util
from lib_properties import pc


# If this is not a directory, should not be displayed.
def Usable(entity_type, entity_ids_arr):
    dir_nam = entity_ids_arr[0]
    return os.path.isdir(dir_nam)

# FIXME:
# http://127.0.0.1:9000/survol/sources_types/CIM_Directory/file_directory.py?xid=CIM_Directory.Name=%2Fmnt%2Fc%2FWindows%2FSystem32
# AddStat:[Errno 2] No such file or directory: '/mnt/c/Windows/System32/%24Acer%24.cmd'
# Later correctly displayed as: /mnt/c/Windows/System32/$Acer$.cmd

# This returns an url which displays a directory in HTML.
# This can work only if the HTTP server allows so. Purely experimental.
# Apache option:
# Alias /MyHome "C:/Users/jsmith"
# <Directory "C:/Users/jsmith/>
#     Options +Indexes
# </Directory>
#
# Maybe read Apache configuration ? IIS also allows to browse a directory.
#
# Apache Icons: http://127.0.0.1/icons/folder.gif
# http://127.0.0.1/icons/sound2.gif
#
# TODO: This is hard-coded, and should be replaced by a Python CGI server serving this directory.
def _url_to_directory(full_dir_path):
    dir_prefix = "C://Users/CurrentUser"
    if full_dir_path.startswith(dir_prefix):
        short_path = full_dir_path[len(dir_prefix):]
        shortpathclean = short_path.replace("&", "&amp;")
        # TODO: This is an experimental feature.
        dir_url = "http://127.0.0.1/Home/" + shortpathclean
        return lib_common.NodeUrl(dir_url)
    return None


# Used only here.
def _uri_directory_direct_script(dir_nam):
    # This should rather have the property pc.property_script, but it must be listed with the files.
    return lib_uris.gUriGen.node_from_script_args(
        '/sources_types/CIM_Directory/file_directory.py',
        "CIM_Directory",
        lib_util.EncodeUri(dir_nam))


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    fil_nam = cgiEnv.GetId()

    # Maybe this is a disk name, on Windows, such as "A:", "C:" etc...
    if lib_util.isPlatformWindows :
        # Remove the trailing backslash.
        if re.match(r"^[a-zA-Z]:\\$", fil_nam):
            fil_nam = fil_nam[:2]
        # Add a slash at the end, otherwise it does not work.
        if re.match("^[a-zA-Z]:$", fil_nam):
            fil_nam += "/"

    fil_node = lib_uris.gUriGen.DirectoryUri(fil_nam)

    grph = cgiEnv.GetGraph()

    if lib_util.isPlatformLinux:
        is_top_directory = fil_nam == '/'
    elif lib_util.isPlatformWindows:
        # Should be "E:/" but in case it would be "E:".
        is_top_directory = (len(fil_nam) == 2 and fil_nam[1] == ':') or (len(fil_nam) == 3 and fil_nam[1:3] == ':/')
    else:
        is_top_directory = False

    logging.debug("fil_nam=%s is_top_directory=%d", fil_nam, is_top_directory)

    if not is_top_directory:
        topdir = os.path.dirname(fil_nam)
        logging.debug("topdir=%s", topdir)
        if topdir:
            topdir_node = lib_uris.gUriGen.DirectoryUri(topdir)
            grph.add((topdir_node, pc.property_directory, fil_node))

            url_mime = _uri_directory_direct_script(topdir)
            grph.add((topdir_node, pc.property_rdf_data_nolist2, lib_common.NodeUrl(url_mime)))

    if os.path.isdir(fil_nam):
        # In case we do not loop at all, the value must be set.
        dirs = None

        # This takes the list of files and directories of this directory, without recursing.
        for subdir, dirs, files in os.walk(fil_nam):
            break

        if dirs == None:
            lib_common.ErrorMessageHtml("No files in:" + fil_nam)

        # Special case if top of the filesystem, on Linux.
        fil_nam_slash = fil_nam
        if fil_nam != "/":
            fil_nam_slash += "/"

        for one_directory in dirs:
            full_dir_path = fil_nam_slash + one_directory
            subdir_node = lib_uris.gUriGen.DirectoryUri(full_dir_path.replace("&", "&amp;"))
            grph.add((fil_node, pc.property_directory, subdir_node))

            url_dir_node = _url_to_directory(full_dir_path)
            if not url_dir_node is None:
                grph.add((subdir_node, pc.property_rdf_data_nolist1, url_dir_node))

            url_mime = _uri_directory_direct_script(full_dir_path)
            grph.add((subdir_node, pc.property_rdf_data_nolist2, lib_common.NodeUrl(url_mime)))

        # TODO: If this is a script, checks if this is executable ?
        for one_file in files:
            full_file_path = fil_nam_slash + one_file
            # First replace the ampersand, then encode.

            full_file_path = lib_util.urllib_quote(full_file_path, safe='/:! ~+{}')

            file_path_replace_encoded = full_file_path.replace("&", "&amp;")

            # There might be non-ascii chars, accents etc...
            # fil_nam='C://Users/Rapha\xeblle \xe0 la plage.jpg'
            # fil_nam='C://Users/Raphaelle a la plage.jpg'
            # Typical Graphviz error:
            # Error: not well-formed (invalid token) in line 1
            # ... <u>Yana (e trema) lle et Constantin (a grave accent) Boulogne-sur-Mer.IMG-20190806-WA0000.jpg ...

            subfil_node = lib_uris.gUriGen.FileUri(file_path_replace_encoded)

            grph.add((fil_node, pc.property_directory, subfil_node))

            # This adds size infoematon about the file.
            CIM_DataFile.AddStat(grph, subfil_node, full_file_path)
            # This adds an URL displaying the file as a MIME document.
            CIM_DataFile.AddHtml(grph, subfil_node, full_file_path)

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory])


if __name__ == '__main__':
    Main()
