#!/usr/bin/env python

"""
Processes returned by WBEM
"""

import sys
import logging
import lib_util
import lib_wbem
import lib_common
from lib_properties import pc

CanProcessRemote = True

# NOTE: This can be used on a Windows machine as long as the remote host runs Linux.
# Usable = lib_util.UsableLinux


def Main():
    # TODO: The type should really be an integer.
    cgiEnv = lib_common.CgiEnv(can_process_remote=True)

    # http://192.168.1.88
    machine_name = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    cimom_url = lib_wbem.HostnameToWbemServer(machine_name)

    logging.debug("wbem_hostname_processes.py machine_name=%s cimom_url=%s", machine_name, cimom_url)

    # If running on the local machine, pass the host as None otherwise authorization is checked
    # just like a remote machine, which means User Account Control (UAC) disabling,
    # and maybe setting LocalAccountTokenFilterPolicy=1
    if lib_util.is_local_address(machine_name):
        server_box = lib_common.gUriGen
    else:
        server_box = lib_common.RemoteBox(machine_name)

    # >>> conn = pywbem.WBEMConnection("http://192.168.1.88:5988" , ('pe***us','t*t*') )
    try:
        conn_wbem = lib_wbem.WbemConnection(cimom_url)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Connecting to :" + cimom_url + " Caught:" + str(exc))

    try:
        lst_proc = conn_wbem.EnumerateInstances(ClassName="PG_UnixProcess", namespace="root/cimv2")
    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:" + str(exc))

    # We should be using the class CMI_Process instead of PG_UnixProcess but it returns the error:
    # Python 2.7, pywbem.__version__ '0.8.0-dev'
    # >>> conn = pywbem.WBEMConnection("https://192.168.1.88:5989" , ('my-user','my-pass') )
    # >>> lst = conn.EnumerateInstanceNames(ClassName="CIM_Process",namespace="root/cimv2")
    # ...pywbem.cim_operations.CIMError: (1, u'CIM_ERR_FAILED: Error initializing CMPI MI /home/rchateau/TestProviderOpenLMI/tutorial_final/T
    # UT_UnixProcess.py, the following MI factory function(s) returned an error: _Generic_Create_InstanceMI, message was: cmpi:Traceback (
    # most recent call last):<br>  File "/usr/lib64/python2.7/site-packages/cmpi_pywbem_bindings.py", line 34, in <module><br>    from pyw
    # bem.cim_provider2 import ProviderProxy<br>ImportError: No module named cim_provider2<br>')

    # >>> lst_proc[3].keys()
    # [u'OSCreationClassName', u'UserModeTime', u'Parameters', u'ExecutionState', u'ProcessGroupID', u'Priority', u'OtherExecutionDescript
    # ion', u'Handle', u'Description', u'RealUserID', u'CSCreationClassName', u'ProcessTTY', u'OSName', u'ProcessSessionID', u'CreationCla
    # ssName', u'WorkingSetSize', u'Name', u'CSName', u'ParentProcessID', u'KernelModeTime', u'Caption', u'ProcessNiceValue']

    # With a dictionary, so the nodes are created once only.
    Main.dictWbemPidToNode = {}

    def wbem_pid_to_node(proc_id):
        logging.debug("procId=%s", proc_id)
        try:
            return Main.dictWbemPidToNode[proc_id]
        except KeyError:
            node = server_box.PidUri(proc_id)

            Main.dictWbemPidToNode[proc_id] = node
            return node

    for one_proc in lst_proc:
        node_process = wbem_pid_to_node(one_proc["Handle"])
        parent_node_process = wbem_pid_to_node(one_proc["ParentProcessID"])

        grph.add((node_process, pc.property_ppid, parent_node_process))

        grph.add((node_process, pc.property_information, lib_util.NodeLiteral(one_proc["Caption"])))

        if False:
            if one_proc["Caption"] != one_proc["Description"]:
                grph.add((node_process, lib_common.MakeProp("Description"), lib_util.NodeLiteral(one_proc["Description"])))

            for prpNam in ["WorkingSetSize","KernelModeTime","ProcessNiceValue","OtherExecutionDescription"]:
                try:
                    grph.add((node_process, lib_common.MakeProp(prpNam), lib_util.NodeLiteral(one_proc["prpNam"])))
                except KeyError:
                    pass

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
