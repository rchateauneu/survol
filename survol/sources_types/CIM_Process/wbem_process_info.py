#!/usr/bin/env python

"""
WBEM CIM_Process information.
"""

import sys
import lib_util
import lib_common
import lib_wbem
from lib_properties import pc

Usable = lib_util.UsableLinux

CanProcessRemote = True

def Main():
    # TODO: can_process_remote should be suppressed because it duplicates CanProcessRemote
    cgiEnv = lib_common.CgiEnv(can_process_remote=True)
    pid = int(cgiEnv.GetId())
    machine_name = cgiEnv.GetHost()

    grph = cgiEnv.GetGraph()

    cimom_url = lib_wbem.HostnameToWbemServer(machine_name)

    DEBUG("wbem_process_info.py currentHostname=%s pid=%d machine_name=%s cimom_url=%s",
          lib_util.currentHostname, pid, machine_name, cimom_url)

    conn_wbem = lib_wbem.WbemConnection(cimom_url)

    name_space = "root/cimv2"
    try:
        inst_lists = conn_wbem.ExecQuery("WQL", 'select * from CIM_Process  where Handle="%s"' % pid, name_space)
    except:
        lib_common.ErrorMessageHtml("Error:" + str(sys.exc_info()))

    class_name = "CIM_Process"
    dict_props = {"Handle": pid}

    root_node = lib_util.EntityClassNode(class_name, name_space, cimom_url, "WBEM")

    # There should be only one object, hopefully.
    for an_inst in inst_lists:
        dict_inst = dict(an_inst)

        host_only = lib_util.EntHostToIp(cimom_url)
        if lib_util.IsLocalAddress(host_only):
            uri_inst = lib_common.gUriGen.UriMakeFromDict(class_name, dict_props)
        else:
            uri_inst = lib_common.RemoteBox(host_only).UriMakeFromDict(class_name, dict_props)

        grph.add((root_node, lib_common.MakeProp(class_name), uri_inst))

        url_namespace = lib_wbem.NamespaceUrl(name_space, cimom_url, class_name)
        nod_namespace = lib_common.NodeUrl(url_namespace)
        grph.add((root_node, pc.property_cim_subnamespace, nod_namespace))

        # None properties are not printed.
        for iname_key in dict_inst:
            iname_val = dict_inst[iname_key]
            # TODO: If this is a reference, create a Node !!!!!!!
            if not iname_val is None:
                grph.add((uri_inst, lib_common.MakeProp(iname_key), lib_common.NodeLiteral(iname_val)))

        # TODO: Call the method Associators(). Idem References().

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()
