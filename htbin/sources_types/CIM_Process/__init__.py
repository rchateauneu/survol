import sys
import rdflib
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

def PsutilProcToUser(proc):
	try:
		return proc.username()
	except TypeError:
		return proc.username
	except AccessDenied:
		return "AccessDenied"

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

################################################################################

def EntityOntology():
	return ( ["Handle"],)

# Each entity can have such a file with its name as file name.
# Then in its file, by convention adds information to a node.
def AddInfo(grph,node,entity_ids_arr):
	pidProc = entity_ids_arr[0]
	# sys.stderr.write("AddInfo entity_id=%s\n" % pidProc )
	grph.add( ( node, pc.property_pid, rdflib.Literal(pidProc) ) )
	try:
		proc_obj = psutil.Process(int(pidProc))

		cmd_line = PsutilProcToCmdline(proc_obj)
		grph.add( ( node, pc.property_command, rdflib.Literal(cmd_line) ) )

		( execName, execErrMsg ) = PsutilProcToExe(proc_obj)
		if execName == "":
			grph.add( ( node, pc.property_runs, rdflib.Literal("Executable error:"+execErrMsg) ) )
			exec_node = None
		else:
			exec_node = lib_common.gUriGen.FileUri( execName )
			grph.add( ( node, pc.property_runs, exec_node ) )

		user_name = PsutilProcToUser(proc_obj)
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
		grph.add( ( node, pc.property_information, rdflib.Literal(str(exc)) ) )


