# Replacement of psutil if it cannot be installed (mutualised hosting, embedded hardware etc...)

import os
import sys
import lib_common
import lib_util

################################################################################

try:
	import psutil

	# Different exceptions depending on psutil version.
	try:
		# Which psutil version ?
		from psutil import NoSuchProcess
		from psutil import AccessDenied
	except ImportError:
		from psutil._error import NoSuchProcess
		from psutil._error import AccessDenied

	# Internal CIM_Process use only.
	def PsutilGetProcObjNoThrow(pid):
		return psutil.Process(pid)

	# This isolates
	def ProcessIter():
		return psutil.process_iter()

except ImportError:
	import glob

	class NoSuchProcess:
		def __init__(self):
			pass

	class AccessDenied:
		def __init__(self):
			pass




	# $ cat /proc/self/status
	# Name:   cat
	# State:  R (running)
	# Tgid:   22346
	# Ngid:   0
	# Pid: 22346
	# PPid:   13095
	# TracerPid:      0
	# Uid: 31896      31896   31896   31896
	# Gid: 100        100     100     100
	# FDSize: 256
	# Groups: 100
	# NStgid: 22346
	# NSpid:  22346
	# NSpgid: 22346
	# NSsid:  13095
	# VmPeak:     3672 kB
	# VmSize:     3672 kB
	# VmLck:         0 kB
	# VmPin:         0 kB
	# VmHWM:      1584 kB
	# VmRSS:      1584 kB
	# VmData:      312 kB
	# VmStk:       132 kB
	# VmExe:        48 kB
	# VmLib:      1604 kB
	# VmPTE:        16 kB
	# VmPMD:         8 kB
	# VmSwap:        0 kB
	# Threads:        1
	# SigQ:   0/16382
	# SigPnd: 0000000000000000
	# ShdPnd: 0000000000000000
	# SigBlk: 0000000000000000
	# SigIgn: 0000000000000000
	# SigCgt: 0000000000000000
	# CapInh: 0000000000000000
	# CapPrm: 0000000000000000
	# CapEff: 0000000000000000
	# CapBnd: 0000003fffffffff
	# CapAmb: 0000000000000000
	# Seccomp:        0
	# Cpus_allowed:   ff
	# Cpus_allowed_list:      0-7
	# Mems_allowed:   00000000,00000001
	# Mems_allowed_list:      0
	# voluntary_ctxt_switches:        2
	# nonvoluntary_ctxt_switches:     0

	# {'VmExe': '3392 kB', 'CapBnd': '0000003fffffffff', 'NSpgid': '29427', 'Tgid': '27794', 'NSpid': '27794', 'VmSize': '15664 kB', 'VmPMD': '8 kB', 'ShdPnd': '0000000000000000', 'State': 'R (running)', 'Gid': '100\t100\t100\t100', 'nonvoluntary_ctxt_switches': '3', 'SigIgn': '0000000001001000', 'VmStk': '132 kB', 'VmData': '6352 kB', 'SigCgt': '0000000180000002', 'CapEff': '0000000000000000', 'VmPTE': '40 kB', 'Groups': '100', 'NStgid': '27794', 'Threads': '1', 'PPid': '19204', 'VmHWM': '13120 kB', 'NSsid': '29427', 'VmSwap': '0 kB', 'Name': 'survolcgi.py', 'SigBlk': '0000000000000000', 'Mems_allowed_list': '0', 'VmPeak': '15724 kB', 'Ngid': '0', 'VmLck': '0 kB', 'SigQ': '0/128505', 'VmPin': '0 kB', 'Mems_allowed': '00000000,00000001', 'CapPrm': '0000000000000000', 'CapAmb': '0000000000000000', 'Seccomp': '0', 'VmLib': '5044 kB', 'Cpus_allowed': 'ff', 'Uid': '31896\t31896\t31896\t31896', 'SigPnd': '0000000000000000', 'Pid': '27794', 'Cpus_allowed_list': '0-7', 'TracerPid': '0', 'CapInh': '0000000000000000', 'voluntary_ctxt_switches': '1039', 'VmRSS': '13088 kB', 'FDSize': '128'}

	# This can work on Linux only.
	class MyProcObj:
		def __init__(self,aPid):
			self.m_proc = "/proc/" + str(aPid)
			self.pid = aPid
			try:
				self.m_props = { lin[0]:" ".join(lin[1:]).strip() for lin in [ li.split(":") for li in open(self.m_proc+"/status","r").readlines() ] }
			except:
				self.m_props = {}

		def memory_info(self):
			class MemInfo (object):
				def __init__(self):
					self.rss = 0
					self.vms = 0
			return MemInfo()

		def ppid(self):
			try:
				return int(self.m_props["PPid"])
			except KeyError:
				return 0

		def name(self):
			try:
				return self.m_props["Name"]
			except KeyError:
				return ""

		def username(self):
			# Uid: 31896\t31896\t31896\t31896
			try:
				uid = self.m_props["Uid"].split("\t")[0]
				return str(uid)
			except KeyError:
				return "nobody"

		def get_open_files(self):
			return []

		def exe(self):
			try:
				return os.readlink(self.m_proc+'/exe')
			except:
				return "Pid %s: No executable" % str(self.pid)

		def cmdline(self):
			try:
				file = open(self.m_proc+'/cmdline', 'r')
				text = file.read()
				file.close()
				return [ text ]
			except:
				return [ "No command" ]

		def connections(self,kind):
			return []

		def memory_maps(self):
			mapLs = []
			# f744c000-f7457000 r-xp 00000000 fa:00 416135                             /lib/i386-linux-gnu/libnss_files-2.19.so
			fil = open(self.m_proc+'/maps', 'r')
			for lin in fil:
				try:
					idx = lin.find("/")
					oneMap = lin[idx:]
					mapLs.append(oneMap)
				except:
					pass
			fil.close()
			return mapLs

		def cwd(self):
			return os.readlink(self.m_proc+'/cwd')


	# Internal CIM_Process use only.
	def PsutilGetProcObjNoThrow(pid):
		return MyProcObj(pid)

	def ProcessIter():
		listProcs = glob.glob('/proc/[0-9]*')
		listPids = [ MyProcObj(int(aProc.split("/")[2])) for aProc in listProcs ]
		return listPids


################################################################################

def PsutilGetProcObj(pid):
	# Very often, a process vanishes quickly so this error happens often.
	try:
		return PsutilGetProcObjNoThrow(pid)
	except NoSuchProcess:
		lib_common.ErrorMessageHtml("No such process:"+str(pid))

# If psutil is not available, consider "getpass.getuser()"
def GetCurrentUser():
	try:
		# This is for OVH
		import getpass
		return getpass.getuser()
	except ImportError:
		currProc = PsutilGetProcObj(os.getpid())
		return PsutilProcToUser(currProc)
	

# https://pythonhosted.org/psutil/
# rss: this is the non-swapped physical memory a process has used.
# On UNIX it matches "top" RES column (see doc).
# On Windows this is an alias for wset field and it matches "Mem Usage" column of taskmgr.exe.
def PsutilResidentSetSize(proc):
	return lib_util.AddSIUnit(proc.memory_info().rss,"B")

# https://pythonhosted.org/psutil/
# vms: this is the total amount of virtual memory used by the process.
# On UNIX it matches "top" VIRT column (see doc).
# On Windows this is an alias for pagefile field and it matches "Mem Usage" "VM Size" column of taskmgr.exe.
def PsutilVirtualMemorySize(proc):
	return lib_util.AddSIUnit(proc.memory_info().vms,"B")

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
		procNam = proc.name()
		# Very often, the process name will just be the executable file name.
		# So we shorten because it is nicer.
		if procNam.upper().endswith(".EXE"):
			procNam = procNam[:-4]
		return procNam
	except TypeError:
		# Old psutil version.
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

