#!/usr/bin/env python

"""
Java properties
"""

# TODO: See this: http://jpype.sourceforge.net/

import os
import os.path
import sys
import lib_util
import lib_uris
import lib_common
from lib_properties import pc


def Usable(entity_type, entity_ids_arr):
    """Can run with Java files only"""

    fil_nam = entity_ids_arr[0]

    # But probably it is not enough and we should try to open it.
    fil_ext = os.path.splitext(fil_nam)[1]
    return fil_ext.lower() in _java_extensions


def _add_java_info_to_java(grph, node, fil_nam):
    """This displays information about a *.java file"""
    filename_no_ext, file_extension = os.path.splitext(fil_nam)

    fil_assoc_nam = filename_no_ext + ".class"

    if os.path.isfile(fil_assoc_nam):
        fil_assoc_node = lib_uris.gUriGen.FileUri(fil_assoc_nam)
        grph.add((node, lib_util.MakeProp("Java class file"), fil_assoc_node))


def _add_java_info_to_class(grph, node, fil_nam):
    """This displays information about a *.class Java file"""
    filename_no_ext, file_extension = os.path.splitext(fil_nam)

    fil_assoc_nam = filename_no_ext + ".java"

    if os.path.isfile(fil_assoc_nam):
        fil_assoc_node = lib_uris.gUriGen.FileUri(fil_assoc_nam)
        grph.add((node, lib_util.MakeProp("Java source file"), fil_assoc_node))


def _add_java_info_to_jar(grph, node, fil_nam):
    try:
        import zipfile
    except ImportError:
        # This cannot do anything if the file cannot be compressed.
        return

    with zipfile.ZipFile(fil_nam, 'r') as zip_obj:
        list_of_files = zip_obj.infolist()
        # TODO: These files exist only in the jar.
        for one_file in list_of_files:
            fil_jar_node = lib_uris.gUriGen.FileUri(one_file)
            grph.add((fil_jar_node, lib_util.MakeProp("Zipped"), lib_util.NodeLiteral(one_file.filename)))
            grph.add((fil_jar_node, lib_util.MakeProp("Size"), lib_util.NodeLiteral(one_file.file_size)))
            grph.add((fil_jar_node, lib_util.MakeProp("Creation time"), lib_util.NodeLiteral(one_file.date_time)))
            grph.add((fil_jar_node, lib_util.MakeProp("Compress size"), lib_util.NodeLiteral(one_file.compress_size)))
            grph.add((node, lib_util.MakeProp("Zipped file"), fil_jar_node))


_java_extensions = {
    ".java": _add_java_info_to_java,
    ".class": _add_java_info_to_class,
    ".jar": _add_java_info_to_jar}


def _add_java_associated_files(grph, node, fil_nam):
    """This adds extra nodes to a file related to Java"""
    filename_no_ext, file_extension = os.path.splitext(fil_nam)
    _java_extensions[file_extension](grph, node, fil_nam)


def Main():
    cgiEnv = lib_common.CgiEnv()

    java_fil_nam = cgiEnv.GetId()

    # sys.stderr.write("dbFilNam=%s\n"%dbFilNam)

    grph = cgiEnv.GetGraph()

    fil_node = lib_common.gUriGen.FileUri(java_fil_nam)

    try:
        _add_java_associated_files(grph, fil_node, java_fil_nam)
    except Exception as exc:
        lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % (java_fil_nam, str(exc)))


    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
    Main()

# https://en.wikipedia.org/wiki/Java_class_file
# Class files are identified by the following 4 byte header (in hexadecimal): CA FE BA BE (the first 4 entries in the table below).