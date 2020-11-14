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


def GetEnvVarMap(the_pid):
    """Returns the value of an environment variable of a given process."""

    # TODO: Apparently, it exists in psutil.Process().environ() ??
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


def _add_command_line_and_executable(grph, node, proc_obj):
    cmd_line = PsutilProcToCmdline(proc_obj)

    node_cmd_line = rdflib.Literal(cmd_line)
    grph.add((node, pc.property_command, rdflib.Literal(cmd_line)))

    exec_name, exec_err_msg = PsutilProcToExe(proc_obj)
    if exec_name == "":
        grph.add((node, pc.property_runs, rdflib.Literal("Executable error:" + exec_err_msg)))
    else:
        exec_node = lib_common.gUriGen.FileUri(exec_name)
        grph.add((node, pc.property_runs, exec_node))

    return node_cmd_line


def _command_line_argument_to_node(process_cwd, file_path):
    if process_cwd is None:
        return None

    # TODO: If it starts with "-" or "--", or "/" or Windows, then it might be an option

    if lib_util.isPlatformWindows and file_path.startswith("\\??\\"):
        # Corner case on Windows: file_path=r"\??\C:\windows\system32\conhost.exe"
        file_path = file_path[4:]
    full_path = os.path.join(process_cwd, file_path)

    # TODO: Should simply try if the path is valid.
    sys.stderr.write("_command_line_argument_to_node full_path=%s\n" % full_path)
    if os.path.exists(full_path):
        if os.path.isdir(full_path):
            sys.stderr.write("_command_line_argument_to_node DIR:%s\n" % full_path)
            return lib_common.gUriGen.DirectoryUri(full_path)
        elif os.path.isfile(full_path):
            sys.stderr.write("_command_line_argument_to_node FILE:%s\n" % full_path)
            return lib_common.gUriGen.FileUri(full_path)
        else:
            sys.stderr.write("_command_line_argument_to_node INVALID:%s\n" % full_path)
    return None


def add_command_line_arguments(grph, node, proc_obj):
    """
    The input is a psutil process object. This adds to the input node triples describing
    all parameters of the command line of the process.
    """

    # TODO: The command line could be a classe because it can be found:
    # TODO: - In a process.
    # TODO: - In a makefile or a Visual Studio vcxproj file, and an ANT file.
    # TODO: A command is an unique concept which can be shared by several processes.
    # TODO: If a node is replaced by a BNode (blank node), then it could be a pattern
    # TODO: to describe a set of command line where only some terms change.

    # TODO: The string should probably be encoded in B64 and prefixed for example by "B64".
    # TODO: If the input string also starts with "B64", it must be encoded no matter what.
    # TODO: It should happen very rarely, so should not be annoying,

    # TODO: HOW TO SORT ARGUMENTS ? Several solutions:
    # TODO: Property "argv?key=1"
    # TODO: This must be consistent with sorting filenames in SVG tables.
    # TODO: The key must be stripped when processing collapsed properties.

    # TODO: Rename "collapsed properties" to "tabular properties" and use the same concept for reports,
    # TODO: Because this is a similar problem of sorting successive values with a key,
    # TODO: the difference being that all values come at once, instead of successive values indexed by time.

    node_cmd_line = _add_command_line_and_executable(grph, node, proc_obj)

    proc_cwd, proc_msg = PsutilProcCwd(proc_obj)

    lib_properties.add_property_metadata_to_graph(grph, pc.property_argv, pc.meta_property_collapsed)

    cmd_array = PsutilProcToCmdlineArray(proc_obj)
    for argv_index, argv_value in enumerate(cmd_array):
        if argv_index == 0:
            # No need to display twice the command.
            continue
        # On pourrait plutot adjoindre un node "key" a chaque node, et utiliser des BNode pour les literales ?
        argv_property = pc.property_argv # lib_properties.MakeProp("argv", key=argv_index)

        argv_node = _command_line_argument_to_node(proc_cwd, argv_value)
        if not argv_node:
            # Default literal value if it was not possible to create a node for the value.
            argv_node = rdflib.Literal(argv_value)
        grph.add((node_cmd_line, argv_property, argv_node))

    # Comment renvoyer le fait qu'il faut afficher ainsi ?
    # cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_directory])
    # Et de plus, on veut a terme mettre les "collapsed properties" dans le CgiEnv qui est fabrique
    # avant d'alimenter le graph ?
    # See: add_property_metadata_to_graph(grph, pc.property_argv, pc.meta_property_collapsed)


def AddInfo(grph, node, entity_ids_arr):
    pid_proc = entity_ids_arr[0]
    exec_node = None
    grph.add((node, pc.property_pid, rdflib.Literal(pid_proc)))
    try:
        proc_obj = psutil.Process(int(pid_proc))

        _add_command_line_and_executable(grph, node, proc_obj)

        # A node is created with the returned string which might as well be
        # an error message, which must be unique. Otherwise all faulty nodes
        # would be merged.
        # TODO: Problem, this node is still clickable. We should return a node
        # of this same type, but with a faulty state, which would make it unclickable.
        user_name = PsutilProcToUser(proc_obj, "User access denied:PID=%s" % pid_proc)

        # TODO: Should add the hostname to the user ???
        user_name_host = lib_common.format_username(user_name)
        user_node = lib_common.gUriGen.UserUri(user_name_host)
        grph.add((node, pc.property_user, user_node))

        sz_resid_set_sz = PsutilResidentSetSize(proc_obj)
        grph.add((node, lib_common.MakeProp("Resident Set Size"), rdflib.Literal(sz_resid_set_sz)))

        sz_virst_mem_sz = PsutilVirtualMemorySize(proc_obj)
        grph.add((node, lib_common.MakeProp("Virtual Memory Size"), rdflib.Literal(sz_virst_mem_sz)))

    except Exception as exc:
        ERROR("CIM_Process.AddInfo. Caught:%s", exc)
        grph.add((node, pc.property_information, rdflib.Literal(str(exc))))

    # Needed for other operations.
    return exec_node


def Usable(entity_type, entity_ids_arr):
    """This should apply to all scripts in the subdirectories: If the process does not exist,
    they should not be displayed by entity.py . The process must be running"""

    pid_proc = entity_ids_arr[0]
    return psutil.pid_exists(pid_proc)


def SelectFromWhere(where_key_values):
    """This must return at least the properties defined in the ontology.
    There is no constraints on the other properties, so the query can return any set of key-value pairs,
    if the minimal set of properties is there."""

    # TODO: Add "select_attributes"
    DEBUG("CIM_Process SelectFromWhere where_key_values=%s", str(where_key_values))
    for proc_obj in psutil.process_iter():
        user_name = PsutilProcToUser(proc_obj,None)
        if user_name:
            user_name_host = lib_common.format_username(user_name)
        else:
            user_name_host = user_name

        parent_pid = proc_obj.ppid()

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
