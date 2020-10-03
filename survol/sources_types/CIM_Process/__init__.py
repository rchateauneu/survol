"""
Standard process. Uniquely associated to a CIM_ComputerSystem and a parent CIM_Process.
"""

import os
import sys
import psutil
import rdflib
import lib_common
import lib_util
from lib_properties import pc
import lib_properties

from lib_psutil import *

################################################################################


# Returns the value of an environment variable of a given process.
# TODO: Apparently, it exists in psutil.Process().environ() ??
def GetEnvVarMap(the_pid):
    if lib_util.isPlatformLinux:
        filproc = open("/proc/%d/environ" % the_pid)
        map_envs = {}
        envlin = filproc.readlines()
        for li in envlin[0].split("\0"):
            pos_equ = li.find("=")
            map_envs[li[:pos_equ] ] = li[pos_equ+1:]
        filproc.close()
        return map_envs

    # https://www.codeproject.com/kb/threads/readprocenv.aspx
    if lib_util.isPlatformWindows:
        # TODO: Not implemented yet.
        return {}

    return {}


def GetEnvVarProcess(the_env_var, the_pid):
    try:
        return GetEnvVarMap(the_pid)[the_env_var]
    except KeyError:
        return None

################################################################################


def EntityOntology():
    return (["Handle"],)


def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]

    # If the process is not there, this is not a problem.
    try:
        proc_obj = psutil.Process(int(entity_id))
        return PsutilProcToName(proc_obj)
    except psutil.NoSuchProcess:
        # This might be, on Windows, a prent process which exit.
        return "Non-existent process:" + entity_id
    except ValueError:
        return "Invalid pid:(" + entity_id + ")"


def AddLinuxCGroup(node, grph):
    if not lib_util.isPlatformLinux:
        return


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph, node, entity_ids_arr):
    pid_proc = entity_ids_arr[0]
    exec_node = None
    grph.add((exec_node, pc.property_pid, rdflib.Literal(pid_proc)))
    try:
        proc_obj = psutil.Process(int(pid_proc))

        cmd_line = PsutilProcToCmdline(proc_obj)
        grph.add((node, pc.property_command, rdflib.Literal(cmd_line)))

        (exec_name, exec_err_msg) = PsutilProcToExe(proc_obj)
        if exec_name == "":
            grph.add((node, pc.property_runs, rdflib.Literal("Executable error:" + exec_err_msg)))
            exec_node = None
        else:
            exec_node = lib_common.gUriGen.FileUri(exec_name)
            grph.add((node, pc.property_runs, exec_node))

        # A node is created with the returned string which might as well be
        # an error message, which must be unique. Otherwise all faulty nodes
        # would be merged.
        # TODO: Problem, this node is still clickable. We should return a node
        # of this smae type, but with a faulty state, which would make it unclickable.
        user_name = PsutilProcToUser(proc_obj, "User access denied:PID=%s" % pid_proc)

        # TODO: Should add the hostname to the user ???
        user_name_host = lib_common.format_username(user_name)
        user_node = lib_common.gUriGen.UserUri(user_name_host)
        grph.add((node, pc.property_user, user_node))

        sz_resid_set_sz = PsutilResidentSetSize(proc_obj)
        grph.add((node, lib_common.MakeProp("Resident Set Size"), rdflib.Literal(sz_resid_set_sz)))

        sz_virst_mem_sz = PsutilVirtualMemorySize(proc_obj)
        grph.add((node, lib_common.MakeProp("Virtual Memory Size"), rdflib.Literal(sz_virst_mem_sz)))

        AddLinuxCGroup(node, grph)

        # TODO: Add the current directory of the process ?

    except Exception as exc:
        ERROR("CIM_Process.AddInfo. Caught:%s", exc)
        grph.add((node, pc.property_information, rdflib.Literal(str(exc))))

    # Needed for other operations.
    return exec_node


# This should apply to all scripts in the subdirectories: If the process does not exist,
# they should not be displayed by entity.py
def Usable(entity_type,entity_ids_arr):
    """Process must be running"""

    pid_proc = entity_ids_arr[0]
    return psutil.pid_exists(pid_proc)


def SelectFromWhere( where_key_values ):
    """This must return at least the properties defined in the ontology.
    There is no constraints on the other.
    TODO: Add "select_attributes" """
    DEBUG("CIM_Process SelectFromWhere where_key_values=%s", str(where_key_values))
    for proc_obj in psutil.process_iter():
        user_name = PsutilProcToUser(proc_obj,None)
        if user_name:
            user_name_host = lib_common.format_username(user_name)
        else:
            user_name_host = user_name

        parent_pid = PsutilProcToPPid(proc_obj)

        if "Handle" in where_key_values and str(where_key_values["Handle"]) != str(proc_obj.pid):
            continue
        if "user" in where_key_values and where_key_values["user"] != user_name_host:
            continue
        if "parent_pid" in where_key_values and str(where_key_values["parent_pid"]) != str(parent_pid):
            continue

        # TODO: Should reuse the existing properties.
        ret_value = {
            lib_properties.MakeProp("Handle"): rdflib.Literal(proc_obj.pid),
            lib_properties.MakeProp("username"): rdflib.Literal(user_name_host),
            lib_properties.MakeProp("parent_pid"): rdflib.Literal(parent_pid)}
        yield ret_value
