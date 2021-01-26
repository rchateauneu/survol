#!/usr/bin/env python

"""
Parent and sub-processes
"""

import psutil
import logging

import lib_common
from sources_types import CIM_Process
from sources_types import CIM_DataFile as lib_entity_file
from lib_properties import pc


def AddExtraInformationtoProcess(grph, node_process, proc_obj):
    CIM_Process.AddInfo(grph, node_process, [str(proc_obj.pid)])

    usr_nam = lib_common.format_username(CIM_Process.PsutilProcToUser(proc_obj))
    user_node = lib_common.gUriGen.UserUri(usr_nam)
    grph.add((user_node, pc.property_owner, node_process))

    (exec_name, exec_err_msg) = CIM_Process.PsutilProcToExe(proc_obj)
    if exec_name != "":
        exec_nod = lib_common.gUriGen.FileUri(exec_name)
        grph.add((node_process, pc.property_runs, exec_nod))
        lib_entity_file.AddInfo(grph, exec_nod, [exec_name])


def tree_subprocesses(grph, proc_obj):
    node_process = lib_common.gUriGen.PidUri(proc_obj.pid)

    try:
        # Old versions of psutil
        subprocs = proc_obj.get_children(recursive=False)
    except Exception:
        # From psutil 3.2.2 at least.
        subprocs = proc_obj.children(recursive=False)

    for child in subprocs:
        node_child = lib_common.gUriGen.PidUri(child.pid)
        grph.add((node_process, pc.property_ppid, node_child))
        AddExtraInformationtoProcess(grph, node_child, child)
        tree_subprocesses(grph, child)


# Recursively add links for the parent processes.
def tree_parent_process(grph, proc_obj, pids_seen_set):
    try:
        the_pid = proc_obj.pid
        if the_pid == 0 or the_pid == 1:
            return

        # A circular processes hierarchy can happen on Windows.
        if the_pid in pids_seen_set:
            logging.warning("Circular pids tree:%d", the_pid)
            return
        pids_seen_set.add(the_pid)

        # Strange, but apparently it can happen.
        the_ppid = proc_obj.ppid()
        if the_ppid == 0:
            return

        node_process = lib_common.gUriGen.PidUri(the_pid)
        node_pprocess = lib_common.gUriGen.PidUri(the_ppid)
        grph.add((node_pprocess, pc.property_ppid, node_process))
        CIM_Process.AddInfo(grph, node_pprocess, [str(the_ppid)])

        AddExtraInformationtoProcess(grph, node_process, proc_obj)

        parent_proc_obj = psutil.Process(int(the_ppid))
        tree_parent_process(grph, parent_proc_obj, pids_seen_set)
    # This exception depends on the version of psutil.
    except CIM_Process.NoSuchProcess:
        # Maybe a process has suddenly disappeared. It does not matter.
        return


def Main():
    cgiEnv = lib_common.CgiEnv()
    try:
        root_pid = int(cgiEnv.GetId())
    except KeyError:
        lib_common.ErrorMessageHtml("Process id should be provided")

    grph = cgiEnv.GetGraph()

    proc_obj = CIM_Process.PsutilGetProcObj(root_pid)

    # Sub-processes, recursion.
    tree_subprocesses(grph, proc_obj)

    # Now display the parent processes.
    # It could be done in a loop instead of recursive calls.
    tree_parent_process(grph, proc_obj, set())

    # This layout style, because the nodes are quite big.
    cgiEnv.OutCgiRdf( "LAYOUT_RECT")
    # cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
