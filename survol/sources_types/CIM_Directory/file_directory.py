#!/usr/bin/python

"""
Files in directory
"""

import os
import re
import sys
import lib_uris
import lib_common
from sources_types import CIM_DataFile
import lib_util
from lib_properties import pc

# If this is not a directory, should not be displayed.
def Usable(entity_type,entity_ids_arr):
    dirNam = entity_ids_arr[0]
    return os.path.isdir(dirNam)

# This returns an url which displays a directory in HTML.
# This can work only if the HTTP server allows so.
# Purely experimental.
# Apache option:
# Alias /Maison "C:/Users/rchateau"
# <Directory "C:/Users/rchateau/>
#     Options +Indexes
# </Directory>
#
# Maybe read Apache configuration ? IIS also allows to browse a directory.
#
# Apache Icons: http://127.0.0.1/icons/folder.gif
# http://127.0.0.1/icons/sound2.gif
#
# TODO: This is hard-coded, and should be replaced by a Python CGI server
# serving this directory.
def UrlDirectory( fullDirPath ):
    # sys.stderr.write("UrlDirectory fullDirPath=%s\n" % fullDirPath)
    dirPrefix = "C://Users/CurrentUser"
    if fullDirPath.startswith( dirPrefix ):
        shortPath = fullDirPath[ len(dirPrefix) : ]
        shortpathclean = shortPath.replace("&","&amp;" )
        dirUrl = "http://127.0.0.1/Home/" + shortpathclean
        return lib_common.NodeUrl(dirUrl)
    return None


# Used only here.
def UriDirectoryDirectScript(dirNam):
    # sys.stderr.write("UriDirectoryDirectScript=%s\n"%dirNam)

    # This should rather have the property pc.property_script, but it must be listed with the files.
    return lib_uris.gUriGen.UriMakeFromScript(
        '/sources_types/CIM_Directory/file_directory.py',
        "CIM_Directory", # TODO: NOT SURE: lib_util.ComposeTypes("file","dir"),
        # pc.property_script,
        lib_util.EncodeUri(dirNam) )


def Main():
    cgiEnv = lib_common.CgiEnv()
    filNam = cgiEnv.GetId()

    # Maybe this is a disk name, on Windows, such as "A:", "C:" etc...
    if lib_util.isPlatformWindows :
        # Remove the trailing backslash.
        if re.match( r"^[a-zA-Z]:\\$", filNam ):
            filNam = filNam[:2]
        # Add a slash at the end, otherwise it does not work.
        if re.match( "^[a-zA-Z]:$", filNam ):
            filNam += "/"

    filNode = lib_common.gUriGen.DirectoryUri(filNam )

    grph = cgiEnv.GetGraph()

    if lib_util.isPlatformLinux:
        isTopDirectory = filNam == '/'
    elif lib_util.isPlatformWindows:
        # Should be "E:/" but in case it would be "E:".
        isTopDirectory = ( len(filNam) == 2 and filNam[1] == ':' ) or ( len(filNam) == 3 and filNam[1:3] == ':/' )
    else:
        isTopDirectory = False

    DEBUG("file_directory.py filNam=%s isTopDirectory=%d", filNam, isTopDirectory)

    if not isTopDirectory:
        topdir = os.path.dirname(filNam)
        DEBUG("topdir=%s",topdir)
        if topdir:
            topdirNode = lib_common.gUriGen.DirectoryUri(topdir )
            grph.add( ( topdirNode, pc.property_directory, filNode ) )

            url_mime = UriDirectoryDirectScript( topdir )
            grph.add( ( topdirNode, pc.property_rdf_data_nolist2, lib_common.NodeUrl(url_mime) ) )

    if os.path.isdir( filNam ):
        # sys.stderr.write("filNam=%s\n"%(filNam))

        # In case we do not loop at all.
        dirs = None
        for subdir, dirs, files in os.walk(filNam):
            break

        if dirs == None:
            lib_common.ErrorMessageHtml("No files in:"+filNam)

        # Special case if top of the filesystem, on Linux.
        filNam_slash = filNam
        if filNam != "/":
            filNam_slash += "/"

        for dir in dirs:
            fullDirPath = filNam_slash + dir
            subdirNode = lib_common.gUriGen.DirectoryUri( fullDirPath.replace("&","&amp;" ) )
            grph.add( ( filNode, pc.property_directory, subdirNode ) )

            url_dir_node = UrlDirectory( fullDirPath )
            if not url_dir_node is None:
                grph.add( ( subdirNode, pc.property_rdf_data_nolist1, url_dir_node ) )

            url_mime = UriDirectoryDirectScript(fullDirPath)
            grph.add( ( subdirNode, pc.property_rdf_data_nolist2, lib_common.NodeUrl(url_mime) ) )

        # TODO: If this is a script, checks if this is executale ?
        for file in files:
            fullFilePath = filNam_slash+file
            # OK WinXP: On remplace d'abord le ampersand, et on encode ensuite, car le remplacement ne marche pas dans l'autre sens.
            subfilNode = lib_common.gUriGen.FileUri( fullFilePath.replace("&","&amp;" ) )

            grph.add( ( filNode, pc.property_directory, subfilNode ) )

            CIM_DataFile.AddStat( grph, subfilNode, fullFilePath )
            CIM_DataFile.AddHtml( grph, subfilNode, fullFilePath )

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory] )
    # cgiEnv.OutCgiRdf("LAYOUT_RECT", [] )

if __name__ == '__main__':
    Main()


