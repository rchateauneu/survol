#!/usr/bin/env python

"""
MBean information
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

    pid_m_bean = cgiEnv.m_entity_id_dict["Handle"]

    # TODO: Not convenient.
    mbean_obj_nam = cgiEnv.m_entity_id_dict["Name"]
    mbean_obj_nam = mbean_obj_nam.replace("*",",").replace("-","=")

    grph = cgiEnv.GetGraph()

    node_process = lib_uris.gUriGen.PidUri(pid_int)


    jmx_data = survol_java.GetJavaDataFromJmx(pid_int, mbean_obj_nam)

    jmx_data_m_beans = jmx_data["allMBeans"]

    prop_m_bean = lib_common.MakeProp("MBean")

    # There should be only one.
    for jmx_m_bean in jmx_data_m_beans:
        cls_nam = jmx_m_bean["className"]
        obj_nam = jmx_m_bean["objectName"]

        if obj_nam != mbean_obj_nam:
            logging.error("THIS SHOULD NOT HAPPEN: %s != %s",obj_nam,mbean_obj_nam)

        # "=sun.management.ManagementFactoryHelper$1[java.nio:type=BufferPool,name=mapped]"
        logging.debug("jmx_m_bean=%s", jmx_m_bean)

        # Not sure about the file name
        node_class = survol_mbean.MakeUri(pid_int, cls_nam)
        grph.add((node_class, lib_common.MakeProp("Object name"), lib_util.NodeLiteral(obj_nam)))

        dict_m_bean_info = jmx_m_bean["info"]
        for keyInfo in dict_m_bean_info:
            val_info = dict_m_bean_info[keyInfo]
            grph.add((node_class, lib_common.MakeProp(keyInfo), lib_util.NodeLiteral(val_info)))

        grph.add((node_class, lib_common.MakeProp("Attributes"), lib_util.NodeLiteral(jmx_m_bean["attrs"])))

        grph.add((node_process, prop_m_bean, node_class))

    cgiEnv.OutCgiRdf()
    # cgiEnv.OutCgiRdf( "LAYOUT_RECT", [prop_m_bean])


if __name__ == '__main__':
    Main()
