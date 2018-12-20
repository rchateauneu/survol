"""
Standard process. Uniquely associated to a CIM_ComputerSystem and a parent CIM_Process.
"""

import os
import sys
import lib_common
import lib_util
from lib_properties import pc

from lib_psutil import *

################################################################################

# Returns the value of an environment variable of a given process.
# TODO: Apparently, it exists in psutil.Process().environ() ??
def GetEnvVarMap(thePid):
	if lib_util.isPlatformLinux:
		filproc = open("/proc/%d/environ"%thePid)
		mapEnvs = {}
		envlin = filproc.readlines()
		for li in envlin[0].split("\0"):
			posEqu = li.find("=")
			mapEnvs[ li[:posEqu] ] = li[posEqu+1:]
		filproc.close()
		return mapEnvs

	# https://www.codeproject.com/kb/threads/readprocenv.aspx
	if lib_util.isPlatformWindows:
		# TODO: Not implemented yet.
		return {}


	return {}

def GetEnvVarProcess(theEnvVar,thePid):
	try:
		return GetEnvVarMap(thePid)[theEnvVar]
	except KeyError:
		return None

################################################################################

def EntityOntology():
	return ( ["Handle"],)

def EntityName(entity_ids_arr):
	entity_id = entity_ids_arr[0]

	#if entity_host and entity_host != lib_util.currentHostname:
	#	return "process id " + entity_id # + "@" + entity_host

	# If the process is not there, this is not a problem.
	try:
		# sys.stderr.write("psutil.Process entity_id=%s\n" % ( entity_id ) )
		proc_obj = PsutilGetProcObjNoThrow(int(entity_id))
		return PsutilProcToName(proc_obj)
	except NoSuchProcess:
		# This might be, on Windows, a prent process which exit.
		return "Non-existent process:"+entity_id
	except ValueError:
		return "Invalid pid:("+entity_id+")"
	# sys.stderr.write("entity_label=%s\n" % ( entity_label ) )

def AddLinuxCGroup(node,grph):
	if not lib_util.isPlatformLinux:
		return

	# cat /proc/self/cgroup

# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	pidProc = entity_ids_arr[0]
	exec_node = None
	# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
	grph.add( ( node, pc.property_pid, lib_common.NodeLiteral(pidProc) ) )
	try:
		proc_obj = PsutilGetProcObjNoThrow(int(pidProc))

		cmd_line = PsutilProcToCmdline(proc_obj)
		grph.add( ( node, pc.property_command, lib_common.NodeLiteral(cmd_line) ) )

		( execName, execErrMsg ) = PsutilProcToExe(proc_obj)
		if execName == "":
			grph.add( ( node, pc.property_runs, lib_common.NodeLiteral("Executable error:"+execErrMsg) ) )
			exec_node = None
		else:
			exec_node = lib_common.gUriGen.FileUri( execName )
			grph.add( ( node, pc.property_runs, exec_node ) )

		# A node is created with the returned string which might as well be
		# an error message, which must be unique. Otherwise all faulty nodes
		# would be merged.
		# TODO: Problem, this node is still clickable. We should return a node
		# of this smae type, but with a faulty state, which would make it unclickable.
		user_name = PsutilProcToUser(proc_obj,"User access denied:PID=%s"%pidProc)

		# TODO: Should add the hostname to the user ???
		user_name_host = lib_common.FormatUser( user_name )
		user_node = lib_common.gUriGen.UserUri(user_name_host)
		grph.add( ( node, pc.property_user, user_node ) )

		szResidSetSz = PsutilResidentSetSize(proc_obj)
		grph.add( ( node, lib_common.MakeProp("Resident Set Size"), lib_common.NodeLiteral(szResidSetSz) ) )

		szVirstMemSz = PsutilVirtualMemorySize(proc_obj)
		grph.add( ( node, lib_common.MakeProp("Virtual Memory Size"), lib_common.NodeLiteral(szVirstMemSz) ) )

		AddLinuxCGroup(node,grph)

		# TODO: Add the current directory of the process ?

	# except psutil._error.NoSuchProcess:
	# Cannot use this exception on some psutil versions
	# AttributeError: 'ModuleWrapper' object has no attribute '_error'
	except Exception as exc:
		exc = sys.exc_info()[1]
		ERROR("CIM_Process.AddInfo. Caught:%s",exc)
		grph.add( ( node, pc.property_information, lib_common.NodeLiteral(str(exc)) ) )

	# Needed for other operations.
	return exec_node


# This should apply to all scripts in the subdirectories: If the process does not exist,
# they should not be displayed by entity.py
def Usable(entity_type,entity_ids_arr):
    """Process must be running"""

    pidProc = entity_ids_arr[0]
    try:
        # Any error, no display.
        proc_obj = PsutilGetProcObjNoThrow(int(pidProc))
        # sys.stderr.write("============================ Process HERE\n")
        return True
    except:
        # sys.stderr.write("============================ Process NOT HERE\n")
        return False

