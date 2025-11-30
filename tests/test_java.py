#!/usr/bin/env python

from __future__ import print_function

import os
import pkgutil

import unittest

from init import *

# This loads the module from the source, so no need to install it, and no need of virtualenv.
update_test_path()

import lib_uris
import lib_util
import lib_client
from sources_types import java as survol_java


_class_exposed_content = """\
Compiled from "SampleClass.java"
class SampleClass {
  int id;
  java.lang.String name;
  SampleClass();
}
"""

_jar_path_name = "tests/SampleJava/SampleClass.jar"


class SurvolBasicJavaTest(unittest.TestCase):
    def test_jar_files_list(self):
        """Test function jar_files_list"""
        list_of_files = survol_java.jar_files_list(_jar_path_name)
        expected_files = []
        self.assertEqual(list_of_files, expected_files)

    def test_jar_classes_list(self):
        list_of_classes = list(survol_java.jar_files_list(_jar_path_name))
        expected_classes = [("SampleClass.class", "SampleClass")]
        self.assertEqual(list_of_classes, expected_classes)

    def test_parse_class_content(self):
        actual_content = survol_java.parse_class_content(_class_exposed_content)
        expected_content = ("SampleClass", ["id", "name"])
        self.assertEqual(actual_content, expected_content)


@unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype cannot be imported.")
class SurvolLocalJpypeTest(unittest.TestCase):

    @unittest.skipIf(is_windows7, "Does not work on Windows 7")
    @unittest.skipIf(is_windows10, "Does not work on Windows 10")
    def test_java_mbeans(self):
        """Java MBeans"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/java_mbeans.py",
            "CIM_Process",
            Handle=CurrentPid)

        list_required = [
            CurrentProcessPath
        ]

        inst_prefix = 'java/mbean.Handle=%d,Name=' % CurrentPid

        for inst_java_name in [
            'java.lang:type-Memory',
            'java.lang:type-MemoryManager*name-CodeCacheManager',
            'java.lang:type-MemoryManager*name-Metaspace Manager',
            'java.lang:type-MemoryPool*name-Metaspace',
            'java.lang:type-Runtime',
            'java.lang:type-MemoryPool*name-PS Survivor Space',
            'java.lang:type-GarbageCollector*name-PS Scavenge',
            'java.lang:type-MemoryPool*name-PS Old Gen',
            'java.lang:type-Compilation',
            'java.lang:type-MemoryPool*name-Code Cache',
            'java.lang:type-Threading',
            'JMImplementation:type-MBeanServerDelegate',
            'java.lang:type-ClassLoading',
            'com.sun.management:type-HotSpotDiagnostic',
            'java.lang:type-MemoryPool*name-PS Eden Space',
            'java.lang:type-OperatingSystem',
            'java.nio:type-BufferPool*name-mapped',
            'com.sun.management:type-DiagnosticCommand',
            'java.lang:type-GarbageCollector*name-PS MarkSweep',
            'java.lang:type-MemoryPool*name-Compressed Class Space',
            'java.nio:type-BufferPool*name-direct',
            'java.util.logging:type-Logging'
        ]:
            list_required.append( inst_prefix + inst_java_name )

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])
        print("test_java_mbeans str_instances_set=", str_instances_set)

        for one_str in list_required:
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(is_windows10, "Does not work on Windows 10 AND IT SHOULD NOT WORK !")
    def test_java_system_properties(self):
        """Java system properties"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/java_system_properties.py",
            "CIM_Process",
            Handle=CurrentPid)

        list_required = [
            CurrentUserPath,
            CurrentProcessPath,
        ]

        required_files = [
            'C:/Windows/System32',
            'C:/Program Files/Java/jre1.8.0_121/lib/charsets.jar',
            'C:/Program Files/nodejs',
            'C:/Program Files/Java/jre1.8.0_121',
            'C:/Windows',
            'C:/windows/Sun/Java/lib/ext',
            'C:/Program Files/Java/jre1.8.0_121/classes',
            'C:/Program Files/Java/jre1.8.0_121/lib/jsse.jar',
            'C:/Program Files/Java/jre1.8.0_121/lib/resources.jar',
            'C:/Program Files/Java/jre1.8.0_121/lib/jce.jar',
            'C:/Program Files/Java/jdk1.8.0_121/lib/tools.jar',
            '.',
            'C:/Program Files/Java/jre1.8.0_121/lib/sunrsasign.jar',
            'C:/Program Files/Java/jre1.8.0_121/lib/endorsed',
            'C:/Program Files/Java/jre1.8.0_121/bin',
            'C:/Program Files/Java/jre1.8.0_121/lib/ext',
            'C:/Windows/System32/WindowsPowerShell/v1.0',
            'C:/Program Files/Java/jdk1.8.0_121/jre/bin',
            'C:/Program Files/Java/jre1.8.0_121/lib/rt.jar',
            'C:/Program Files/Java/jdk1.8.0_121/bin',
            'C:/windows/Sun/Java/bin',
            'C:/Python27',
        ]

        for one_file_path in required_files:
            list_required.append(lib_uris.PathFactory().CIM_Directory(Name=one_file_path))

        raw_instances = my_source.get_triplestore().get_instances()
        str_instances_set = set([str(one_inst) for one_inst in raw_instances])
        for one_inst_str in sorted(str_instances_set):
            print("    one_inst_str=", lib_util.SplitPath(one_inst_str))

        for one_str in list_required:
            if one_str not in str_instances_set:
                print("Not there:", one_str)
            self.assertTrue(one_str in str_instances_set, "test_java_system_properties: Not there:%s" % str(one_str))

    def test_java_jdk_jstack(self):
        """Information about JDK stack"""

        my_source = lib_client.SourceLocal(
            "sources_types/CIM_Process/languages/java/jdk_jstack.py",
            "CIM_Process",
            Handle=CurrentPid)

        # Start a Java process.

        str_instances_set = set([str(one_inst) for one_inst in my_source.get_triplestore().get_instances()])

        self.assertTrue(str_instances_set == set())


class SurvolLocalJavaTest(unittest.TestCase):
    def test_java_properties(self):
        """Investigate Java files"""
        file_path = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SampleJavaFile.java")

        source_java_properties = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/java_properties.py",
            "CIM_DataFile",
            Name=file_path)
        java_properties_json = source_java_properties.content_json()

        print("java_properties_json=", java_properties_json)
        print("java_properties_json=", list(java_properties_json.keys()))
        self.assertEqual(java_properties_json["page_title"], "Java properties SampleJavaFile.java\nStandard data file.")
        self.assertEqual(java_properties_json["nodes"], [])
        self.assertEqual(java_properties_json["links"], [])
