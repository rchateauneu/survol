import sys
import psutil
import lib_common
import lib_util
from lib_properties import pc

################################################################################

# Different exceptions depending on psutil version.
try:
	# Which psutil version ?
	from psutil import NoSuchProcess
	from psutil import AccessDenied
except ImportError:
	from psutil._error import NoSuchProcess
	from psutil._error import AccessDenied

# Very often, a process vanishes quickly so this error happens often.
def PsutilGetProcObj(pid):
	try:
		return psutil.Process(pid)
	except NoSuchProcess:
		lib_util.InfoMessageHtml("No such process:"+str(pid))
		sys.exit(0)


################################################################################
# These functions because of differences between psutil versions.

def PsutilProcToPPid(proc):
	try:
		return proc.ppid()
	except TypeError:
		# psutil "0.7.0" 2009
		return proc.ppid

def PsutilProcToName(proc):
	try:
		# WinXP, old version
		return proc.name()
	except TypeError:
		return proc.name

def PsutilProcToUser(proc,dfltUser = "AccessDenied"):
	try:
		return proc.username()
	except TypeError:
		return proc.username
	except AccessDenied:
		return dfltUser

def PsutilProcOpenFiles(proc):
	try:
		return proc.get_open_files()
	except AccessDenied:
		raise
	except Exception:
		return proc.open_files()

def PsutilProcToExe(proc):
	try:
		try:
			return ( proc.exe(), "" )
		except TypeError:
			return ( proc.exe, "" )
	except AccessDenied:
		return ( "", "Access denied" )

def PsutilProcToCmdline(proc):
	try:
		cmdArr = proc.cmdline()
	except TypeError:
		cmdArr = proc.cmdline
	except AccessDenied:
		return "Access denied"

	return ' '.join(cmdArr)

def PsutilProcConnections(proc,kind='inet'):
	try:
		cnnct = proc.get_connections(kind)
	except AttributeError:
		try:
			cnnct = proc.connections(kind)
		except AccessDenied:
			return []
	except AccessDenied:
		return []

	return cnnct

def PsutilProcMemmaps(proc):
	try:
		all_maps = proc.memory_maps()
	except AttributeError:
		# Old psutil version
		all_maps = proc.get_memory_maps()
	return all_maps

# Returns the current working directory.
def PsutilProcCwd(proc):
	try:
		proc_cwd = proc.getcwd()
		proc_msg = None
	except AccessDenied:
		proc_cwd = None
		proc_msg = "Process %d: Cannot get current working directory: %s" % (proc.pid,str(sys.exc_info()))
	except AttributeError:
		try:
			proc_cwd = proc.cwd()
			proc_msg = None
		except :
			proc_cwd = None
			proc_msg = "Process %d: Cannot get current working directory: %s" % (proc.pid,str(sys.exc_info()[1]))

	return (proc_cwd,proc_msg)

################################################################################

# Returns the value of an environment variable of a given process.
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

def EntityName(entity_ids_arr,entity_host):
	entity_id = entity_ids_arr[0]

	if entity_host and entity_host != lib_util.currentHostname:
		return "process id " + entity_id # + "@" + entity_host

	# If the process is not there, this is not a problem.
	try:
		# sys.stderr.write("psutil.Process entity_id=%s\n" % ( entity_id ) )
		proc_obj = psutil.Process(int(entity_id))
		return PsutilProcToName(proc_obj)
	except NoSuchProcess:
		# This might be, on Windows, a prent process which exit.
		return "Non existent process:"+entity_id
	except ValueError:
		return "Invalid pid:("+entity_id+")"
	# sys.stderr.write("entity_label=%s\n" % ( entity_label ) )


# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	pidProc = entity_ids_arr[0]
	# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
	grph.add( ( node, pc.property_pid, lib_common.NodeLiteral(pidProc) ) )
	try:
		proc_obj = psutil.Process(int(pidProc))

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

		# TODO: Add the current directory of the process ?

		# Needed for other operations.
		return exec_node

	# except psutil._error.NoSuchProcess:
	# Cannot use this exception on some psutil versions
	# AttributeError: 'ModuleWrapper' object has no attribute '_error'
	except Exception:
		exc = sys.exc_info()[1]
		grph.add( ( node, pc.property_information, lib_common.NodeLiteral(str(exc)) ) )

# This should apply to all scripts in the subdirectories: If the process does not exist,
# they should not be displayed by entity.py
def Usable(entity_type,entity_ids_arr):
    """Process must be running"""

    pidProc = entity_ids_arr[0]
    try:
        # Any error, no display.
        proc_obj = psutil.Process(int(pidProc))
        # sys.stderr.write("============================ Process HERE\n")
        return True
    except:
        # sys.stderr.write("============================ Process NOT HERE\n")
        return False

