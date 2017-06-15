#!/usr/bin/python

"""
Windows process call stack
"""

import re
import sys
import subprocess
import rdflib
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import symbol as survol_symbol
from sources_types.CIM_Process import CDB

Usable = lib_util.UsableWindows


# 76530000 76640000   kernel32   (export symbols)       C:\Windows\syswow64\kernel32.dll
# 76640000 7670c000   MSCTF      (deferred)
# 767a0000 767b9000   sechost    (deferred)
# 767c0000 76805000   WLDAP32    (deferred)
# 76810000 768ad000   USP10      (deferred)
# 768b0000 769ca000   urlmon     (deferred)
# 769d0000 769e2000   DEVOBJ     (deferred)
# 769f0000 76a47000   SHLWAPI    (deferred)
# 77300000 7730a000   LPK        (deferred)
# 77330000 774b0000   ntdll      (export symbols)       C:\Windows\SysWOW64\ntdll.dll

# 0:000> lm
# start    end        module name
# 00280000 002e9000   tibrv      (deferred)
# 75940000 7658b000   SHELL32    (deferred)
# 76590000 766a0000   kernel32   (export symbols)       C:\Windows\syswow64\kernel32.dll
# 766a0000 767bb000   WININET    (deferred)


# 0:160> k
# ChildEBP RetAddr
# WARNING: Stack unwind information not available. Following frames may be wrong.
# 295cfaa8 765a338a ntdll!DbgBreakPoint
# 295cfab4 77d79f72 kernel32!BaseThreadInitThunk+0x12
# 295cfaf4 77d79f45 ntdll!RtlInitializeExceptionChain+0x63
# 295cfb0c 00000000 ntdll!RtlInitializeExceptionChain+0x36
# 0:160>

def Main():
	cgiEnv = lib_common.CgiEnv()
	try:
		the_pid = int(cgiEnv.GetId())
	except Exception:
		lib_common.ErrorMessageHtml("Must provide a pid")

	if not lib_util.isPlatformWindows:
		lib_common.ErrorMessageHtml("This works only on Windows platforms")

	grph = cgiEnv.GetGraph()

	# Starts a second session
	cdb_fil = lib_common.TmpFile("CdbCommand","cdb")
	cdb_fd = open(cdb_fil.Name,"w")
	cdb_fd.write("lm\n")  # List loaded modules
	cdb_fd.write("k\n")   # Display stack backtrace.
	cdb_fd.write("qd\n")  # Quit and detach.
	cdb_fd.close()

	cdb_cmd = "cdb -p " + str(the_pid) + " -cf " + cdb_fil.Name


	procNode = lib_common.gUriGen.PidUri( the_pid )
	callNodePrev = None

	modules_map = {}

	sys.stderr.write("Starting cdb_cmd=%s\n" % cdb_cmd )
	try:
		cdb_pipe = subprocess.Popen(cdb_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	except WindowsError:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml( "cdb not available: Caught:%s" % str(exc) )

	sys.stderr.write("Started cdb_cmd=%s\n" % cdb_cmd )

	( cdb_output, cdb_err ) = cdb_pipe.communicate()

	# Without decode, "TypeError: Type str does not support the buffer API"
	cdb_str =  cdb_output.decode("utf-8")

	callDepth = 0

	for dot_line in cdb_str.split('\n'):
		# sys.stderr.write("Line=%s\n" % dot_line )

		err_match = re.match(".*parameter is incorrect.*", dot_line )
		if err_match:
			lib_common.ErrorMessageHtml("CDB:"+dot_line)

		# 76590000 766a0000   kernel32   (export symbols)       C:\Windows\syswow64\kernel32.dll
		match_lm = re.match( "[0-9a-fA-F]+ [0-9a-fA-F]+ +([^ ]*) +\(export symbols\) +(.*)", dot_line )
		if match_lm:
			moduleName = match_lm.group(1)
			dllName = match_lm.group(2).strip().replace("\\","/") # .replace(":","COLON")
			sys.stderr.write("moduleName=%s dllName=%s\n" % ( moduleName, dllName ) )
			modules_map[ moduleName ] = dllName
			continue

		# 295cfb0c 00000000 ntdll!RtlInitializeExceptionChain+0x36
		# Another format, maybe because of a 64 bits machine.
		# 00000000`02edff90 00000000`00000000 ntdll!RtlUserThreadStart+0x21
		match_k = re.match( "[`0-9a-fA-F]+ [`0-9a-fA-F]+ ([^!]*)!([^+]*)", dot_line )
		if match_k:
			moduleName = match_k.group(1)
			try:
				dllName = modules_map[ moduleName ]
			except KeyError:
				dllName = moduleName
			funcName = match_k.group(2).strip()
			sys.stderr.write("moduleName=%s dllName=%s funcName=%s\n" % ( moduleName, dllName, funcName ) )

			dllName = CDB.TestIfKnownDll(dllName)

			callNodePrev = survol_symbol.AddFunctionCall( grph, callNodePrev, procNode, funcName, dllName )
			grph.add( ( callNodePrev, rdflib.Literal("Depth"), rdflib.Literal(callDepth) ) )
			callDepth += 1
			continue

		sys.stderr.write("dot_line=%s\n" % dot_line )

	sys.stderr.write("Parsed cdb result\n")


	callNodePrev = survol_symbol.AddFunctionCall( grph, callNodePrev, procNode, None, None )

	CIM_Process.AddInfo( grph, procNode, [ the_pid ] )

	# http://msdn.microsoft.com/en-us/library/windows/hardware/ff539058(v=vs.85).aspx
	#
	# This section describes how to perform basic debugging tasks using
	# the Microsoft Console Debugger (CDB) and Microsoft NT Symbolic Debugger (NTSD).
	# CDB and NTSD are identical in every way, except that NTSD spawns
	# a new text window when it is started, whereas CDB inherits
	# the Command Prompt window from which it was invoked.
	# The instructions in this section are given for CDB,
	# but they work equally well for NTSD. For a discussion
	# of when to use CDB or NTSD, see Debugging Environments.

	################################################################################


	# cgiEnv.OutCgiRdf()
	cgiEnv.OutCgiRdf("LAYOUT_SPLINE")

if __name__ == '__main__':
	Main()


