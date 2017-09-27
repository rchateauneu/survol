#!/usr/bin/python

"""
Process callstack with gdb
"""

import re
import sys
import lib_util
import lib_common
from sources_types import CIM_Process
from sources_types import linker_symbol as survol_symbol
from lib_properties import pc

Usable = lib_util.UsableLinux

# Runs a gdb command and returns the output with some cleanup.
def RunGdbCommand(the_pid,command):
	tmpGdb = lib_common.TmpFile("gdbstack","gdb")
	gdbFilNam = tmpGdb.Name

	gdbFil = open(gdbFilNam,"w")
	gdbFil.write(command + "\n")
	gdbFil.write("quit\n")
	gdbFil.close()

	# TODO: See python/__init__.py which also runs a gdb command.
	gdb_cmd = [ "gdb", "-q", "-p", str(the_pid), "-x", gdbFilNam ]
	sys.stderr.write( "gdb command=%s\n" % ( " ".join( gdb_cmd ) ) )

	try:
		gdb_pipe = lib_common.SubProcPOpen(gdb_cmd)
	#except FileNotFoundError:
	#	lib_common.ErrorMessageHtml("gdb is not available")
	except Exception:
		exc = sys.exc_info()[1]
		lib_common.ErrorMessageHtml("Gdb:"+ str(exc))

	# TODO: How can we get the stderr message: "ptrace: Operation not permitted." which comes after "Attaching to process 6063" ????

	( gdb_last_output, gdb_err ) = gdb_pipe.communicate()

	resu = []

	# Removes the heading information and the lines beginning with a prompt.
	# [rchateau@DuoLnx BY_process]$ gdb  -q -p 6513 -x stack.gdb
	# Attaching to process 6513
	# Reading symbols from /usr/bin/kdeinit...(no debugging symbols found)...done.
	for lin in gdb_last_output.split('\n'):
		sys.stderr.write("rungdb:%s\n" % (lin) )
		# Not sure the prompt is displayed when in non-interactive mode.
		if lin.startswith("(gdb)"): continue
		if lin.startswith("Reading symbols "): continue
		if lin.startswith("Loaded symbols "): continue
		resu.append(lin)


	if len(gdb_err) != 0:
		sys.stderr.write("Err:%s\n" % (gdb_err) )
		lib_common.ErrorMessageHtml("No gdb output:"+gdb_err)

	return resu

def CallParse( execName, grph, procNode, callNodePrev, lin ):
	# TODO: See the content of the parenthesis. Can it be the arguments?

	funcName = None
	fileName = None

	# #5  0xb6f8007c in QApplication::exec () from /usr/lib/qt3/lib/libqt-mt.so.3
	mtch_call_lib = re.match( "^#[0-9]+ +0x[0-9a-f]+ in ([^ ]+) \([^)]*\) from (.*)$", lin )
	if mtch_call_lib:
		funcName = mtch_call_lib.group(1)
		fileName = mtch_call_lib.group(2)
	else:
		# #8  0x0804ebe9 in QGList::~QGList$delete ()
		mtch_call_lib = re.match( "^#[0-9]+ +0x[0-9a-f]+ in ([^ ]+) \([^)]*\)$", lin )
		if mtch_call_lib:
			funcName = mtch_call_lib.group(1)
			fileName = execName

	# TODO: Should add the address or the line number as last parameter.
	return survol_symbol.AddFunctionCall( grph, callNodePrev, procNode, funcName, fileName )

def PassThreads(the_pid, execName, grph, procNode):
	currThr = -1
	callNodePrev = None

	lines = RunGdbCommand( the_pid, "thread apply all bt" )

	for lin in lines:
		sys.stderr.write("Gdb1:%s\n" % (lin) )

		# TODO: On Linux, the light weight process is another process.
		# Thread 1 (Thread -1237260592 (LWP 6513)):
		mtch_thread = re.match("Thread *([0-9]+) .*", lin )
		if mtch_thread:
			currThr = int( mtch_thread.group(1) )
			callNodePrev = None
			continue

		if currThr == -1:
			continue

		callNodePrev = CallParse( execName, grph, procNode, callNodePrev, lin )

		# Reached the end of the call stack.
		if callNodePrev == None:
			currThr = -1

def PassNoThreads(the_pid, execName, grph, procNode):
	callNodePrev = None

	lines = RunGdbCommand( the_pid, "bt" )

	for lin in lines:
		sys.stderr.write("Gdb2:%s\n" % (lin) )

		callNodeNew = CallParse( execName, grph, procNode, callNodePrev, lin )

		# Reached the end of the call stack.
		if callNodeNew == None and callNodePrev != None:
			sys.stderr.write("End2\n")
			break
		callNodePrev = callNodeNew

def Main():
	cgiEnv = lib_common.CgiEnv(
		"http://www.gnu.org/software/gdb/images/archer.jpg")
	try:
		the_pid = int(cgiEnv.GetId())
	except KeyError:
		lib_common.ErrorMessageHtml("Process id should be provided")

	grph = cgiEnv.GetGraph()

	proc_obj = CIM_Process.PsutilGetProcObj(the_pid)

	procNode = lib_common.gUriGen.PidUri( the_pid )
	CIM_Process.AddInfo( grph, procNode, [ str(the_pid) ] )

	( execName, execErrMsg ) = CIM_Process.PsutilProcToExe( proc_obj )
	if( execName == "" ):
		lib_common.ErrorMessageHtml("Cannot gdb:"+execErrMsg)

	PassThreads(the_pid, execName, grph, procNode)

	# If the command did not return anything, it means that
	# there are no threads, so we fall back to the "classical"
	# gdb output format.
	if len(grph) == 0:
		PassNoThreads( the_pid, execName, grph, procNode)

	cgiEnv.OutCgiRdf()

if __name__ == '__main__':
	Main()
