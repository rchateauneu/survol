#!/usr/bin/env python

"""
Process MBeans
"""

import sys
import logging

import lib_uris
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import java as survol_java
from sources_types.java import mbean as survol_mbean
from lib_properties import pc


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    pid_int = int(cgiEnv.GetId())

    grph = cgiEnv.GetGraph()

    node_process = lib_uris.gUriGen.PidUri(pid_int)

    jmx_data = survol_java.GetJavaDataFromJmx(pid_int)
    try:
        jmx_data_m_beans = jmx_data["allMBeans"]
    except KeyError:
        jmx_data_m_beans = []

    prop_m_bean = lib_common.MakeProp("MBean")

    for jmx_m_bean in jmx_data_m_beans:
        cls_nam = jmx_m_bean["className"]
        obj_nam = jmx_m_bean["objectName"]

        # "=sun.management.ManagementFactoryHelper$1[java.nio:type=BufferPool,name=mapped]"
        logging.debug("jmx_m_bean=%s", jmx_m_bean)

        # Not sure about the file name
        node_class = survol_mbean.MakeUri( pid_int, obj_nam)
        grph.add((node_class, lib_common.MakeProp("Class name"), lib_util.NodeLiteral(cls_nam)))

        grph.add((node_process, prop_m_bean, node_class))

    cgiEnv.OutCgiRdf( "LAYOUT_RECT", [prop_m_bean])


if __name__ == '__main__':
    Main()
