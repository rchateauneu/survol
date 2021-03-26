#!/usr/bin/env python

"""
System Properties
"""

import sys
import logging
import lib_util
import lib_common
import lib_uris
from sources_types import CIM_Process
from sources_types import java as survol_java
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pid_int = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    node_process = lib_uris.gUriGen.PidUri(pid_int)

    jmx_props = survol_java.JavaJmxSystemProperties(pid_int)

    logging.debug("jmx_props=%s", str(jmx_props))

    try:
        path_separator = jmx_props["path.separator"]
    except KeyError:
        path_separator = None

    # The properties which should be displayed in matrices instead of individual nodes.
    props_matrix = []

    prop_order = lib_common.MakeProp("Order")

    def process_pathes(keyJmxProp, val_jmx_prop, rdf_prop):
        props_matrix.append(rdf_prop)
        path_split = val_jmx_prop.split(path_separator)
        idx_path = 1
        for dir_nam in path_split:
            # TODO: It should be sorted.
            node_directory = lib_uris.gUriGen.DirectoryUri(dir_nam)

            # TODO: There should be one matrix per box.
            # grph.add( ( node_directory, lib_common.MakeProp("Property"), lib_util.NodeLiteral(key_jmx_prop) ) )

            grph.add((node_directory, prop_order, lib_util.NodeLiteral(idx_path)))
            grph.add((node_process, rdf_prop, node_directory))
            idx_path += 1

    for key_jmx_prop in jmx_props:
        val_jmx_prop = jmx_props[key_jmx_prop]
        rdf_prop = lib_common.MakeProp(key_jmx_prop)

        # These are list of directories separated by ";"
        if key_jmx_prop in [
           "sun.boot.class.path", "java.library.path", "java.ext.dirs", "java.endorsed.dirs", "java.class.path"]:
            process_pathes(key_jmx_prop,val_jmx_prop,rdf_prop)
            continue

        # Some keys are not interesting.
        if key_jmx_prop in ["path.separator", "file.separator", "line.separator",
                          "cpu.endian", "sun.cpu.isalist", "sun.cpu.endian", "sun.arch.data.model",
                          "os.arch", "os.name", "os.version", "sun.os.patch.level",
                          "user.country"," user.language", "user.script", "user.timezone", "user.variant",
                          "sun.awt.enableExtraMouseButtons", "sun.desktop"]:
            continue

        # Redundancy, it prints quite often the same evalue.
        elif key_jmx_prop in ["java.vendor", "java.vm.vendor", "java.vm.specification.vendor"] and val_jmx_prop == jmx_props["java.specification.vendor"]:
            continue

        # Redundancy, prints often the same value.
        if key_jmx_prop in ["sun.jnu.encoding"] and val_jmx_prop == jmx_props["file.encoding"]:
            continue

        # These are individual directories.
        if key_jmx_prop in ["user.dir", "user.home", "java.home", "java.io.tmpdir", "application.home", "sun.boot.library.path"]:
            node_directory = lib_uris.gUriGen.DirectoryUri(val_jmx_prop)
            grph.add((node_process, rdf_prop, node_directory))
            continue

        # User name on this machine.
        if key_jmx_prop in ["user.name"]:
            node_user = lib_uris.gUriGen.UserUri(val_jmx_prop)
            grph.add((node_process, rdf_prop, node_user))
            continue

        # HTTP URLs
        if key_jmx_prop in ["java.vendor.url", "java.vendor.url.bug"]:
            node_java_url = lib_common.NodeUrl(val_jmx_prop)
            grph.add((node_process, rdf_prop, node_java_url))
            continue

        # Maybe a Java package ?????
        # "sun.java.command"

        grph.add((node_process, rdf_prop, lib_util.NodeLiteral(val_jmx_prop)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", props_matrix)


if __name__ == '__main__':
    Main()
