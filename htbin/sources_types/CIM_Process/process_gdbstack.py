#!/usr/bin/python

import re
import sys
import subprocess
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
import lib_entities.lib_entity_symbol as lib_entity_symbol
from lib_properties import pc

cgiEnv = lib_common.CgiEnv(
	"Process callstack with gdb",
	"http://www.gnu.org/software/gdb/images/archer.jpg")
try:
	the_pid = int(cgiEnv.GetId())
except KeyError:
	lib_common.ErrorMessageHtml("Process id should be provided")

# Runs a gdb command and returns the output with some cleanup.
def RunGdbCommand(command):
	tmpGdb = lib_common.TmpFile("gdbstack","gdb")
	gdbFilNam = tmpGdb.Name

	gdbFil = open(gdbFilNam,"w")
	gdbFil.write(command + "\n")
	gdbFil.write("quit\n")
	gdbFil.close()

	gdb_cmd = [ "gdb", "-q", "-p", str(the_pid), "-x", gdbFilNam ]
	sys.stderr.write( "gdb command=%s\n" % ( " ".join( gdb_cmd ) ) )

	try:
		gdb_pipe = subprocess.Popen(gdb_cmd, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

grph = rdflib.Graph()

proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(the_pid)

procNode = lib_common.gUriGen.PidUri( the_pid )
lib_entity_CIM_Process.AddInfo( grph, procNode, [ str(the_pid) ] )

( execName, execErrMsg ) = lib_entity_CIM_Process.PsutilProcToExe( proc_obj )
if( execName == "" ):
	lib_common.ErrorMessageHtml("Cannot gdb:"+execErrMsg)

def CallParse( grph, procNode, callNodePrev, lin ):
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

	lib_entity_symbol.AddFunctionCall( grph, callNodePrev, procNode, funcName, fileName )

def PassThreads(grph, procNode):
	currThr = -1
	callNodePrev = None

	lines = RunGdbCommand( "thread apply all bt" )

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

		callNodePrev = CallParse( grph, procNode, callNodePrev, lin )

		# Reached the end of the call stack.
		if callNodePrev == None:
			currThr = -1

def PassNoThreads(grph, procNode):
	callNodePrev = None

	lines = RunGdbCommand( "bt" )

	for lin in lines:
		sys.stderr.write("Gdb2:%s\n" % (lin) )

		callNodeNew = CallParse( grph, procNode, callNodePrev, lin )

		# Reached the end of the call stack.
		if callNodeNew == None and callNodePrev != None:
			sys.stderr.write("End2\n")
			break
		callNodePrev = callNodeNew

PassThreads(grph, procNode)

# If the command did not return anything, it means that
# there are no threads, so we fall back to the "classical"
# gdb output format.
if len(grph) == 0:
	PassNoThreads(grph, procNode)

cgiEnv.OutCgiRdf(grph)

