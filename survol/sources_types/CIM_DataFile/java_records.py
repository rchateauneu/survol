#!/usr/bin/env python

"""
Java properties
"""

# TODO: See this: http://jpype.sourceforge.net/

import os
import sys
import logging

import lib_util
import lib_uris
import lib_common
from lib_properties import pc
from sources_types import java as survol_java


def Usable(entity_type, entity_ids_arr):
    """Can run with Java files only"""

    fil_nam = entity_ids_arr[0]

    # But probably it is not enough and we should try to open it.
    fil_ext = os.path.splitext(fil_nam)[1]
    return fil_ext.lower() in _java_extensions


def _add_java_classes_from_class(grph, root_node, class_fil_nam):
    """
    This the class from a class file. There should be one only.

    It uses javap:
    https://docs.oracle.com/javase/7/docs/technotes/tools/windows/javap.html

    javap .\SampleClass.class
    """
    javap_class_content = Something("javap %s" % class_fil_nam)
    class_file_node = lib_uris.gUriGen.FileUri(class_fil_nam)
    survol_java.add_class_content_to_graph(grph, class_file_node, javap_class_content)


def _add_java_classes_from_jar(grph, jar_fil_node, jar_fil_nam):
    list_of_classes = survol_java.jar_classes_list(jar_fil_nam)


    for file_path, class_name in list_of_classes:
        # For example: javap -cp .\SampleClass.jar SampleClass
        javap_class_content = Something("javap -cp %s %s" % (jar_fil_nam, class_name))
        # TODO: These class files exist only in the jar. They have a relative path.
        class_file_node = lib_uris.gUriGen.FileUri(file_path)
        grph.add((jar_fil_node, lib_common.MakeProp("Zipped file"), class_file_node))
        survol_java.add_class_content_to_graph(grph, class_file_node, javap_class_content)


_java_extensions = {
    ".class": _add_java_classes_from_class,
    ".jar": _add_java_classes_from_jar}


def _add_java_classes(grph, java_file_node, fil_nam):
    """
    This adds extra nodes to a file related to Java
    """
    filename_no_ext, file_extension = os.path.splitext(fil_nam)
    _java_extensions[file_extension](grph, java_file_node, fil_nam)


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    java_file_path = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    java_file_node = lib_uris.gUriGen.FileUri(java_file_path)

    try:
        _add_java_classes(grph, java_file_node, java_file_path)
    except Exception as exc:
        lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % (java_file_path, str(exc)))

    cgiEnv.OutCgiRdf("LAYOUT_SPLINE")


if __name__ == '__main__':
    Main()

# https://en.wikipedia.org/wiki/Java_class_file
# Class files are identified by the following 4 byte header (in hexadecimal):
# CA FE BA BE (the first 4 entries in the table below).

# For viewing the content of the jar file, simple decompression:
# > jar tf .\SampleClass.jar
# META-INF/
# META-INF/MANIFEST.MF
# SampleClass.class
#
# Content of a class file:
# > javap .\SampleClass.class
# Compiled from "SampleClass.java"
# class SampleClass {
#   int id;
#   java.lang.String name;
#   SampleClass();
# }
#
# One class in a Jar file:
# > javap -cp .\SampleClass.jar SampleClass
# Compiled from "SampleClass.java"
# class SampleClass {
#   int id;
#   java.lang.String name;
#   SampleClass();
# }
# */