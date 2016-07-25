#!/usr/bin/python

"""
Parent and sub-processes
"""

import psutil
import rdflib
import lib_common
import lib_entities.lib_entity_CIM_Process as lib_entity_CIM_Process
from sources_types import CIM_DataFile as lib_entity_file
from lib_properties import pc

def AddExtraInformationtoProcess(grph,node_process,proc_obj):
	lib_entity_CIM_Process.AddInfo( grph, node_process, [ str(proc_obj.pid) ] )

	usrNam = lib_common.FormatUser( lib_entity_CIM_Process.PsutilProcToUser( proc_obj ) )
	userNode = lib_common.gUriGen.UserUri(usrNam)
	grph.add( ( userNode, pc.property_owner, node_process ) )

	( execName, execErrMsg ) = lib_entity_CIM_Process.PsutilProcToExe( proc_obj )
	if execName != "":
		execNod = lib_common.gUriGen.FileUri(execName)
		grph.add( ( node_process, pc.property_runs, execNod ) )
		lib_entity_file.AddInfo( grph, execNod, [ execName ] )

def tree_subprocesses(grph, proc_obj):
	if lib_common.UselessProc(proc_obj):
		return

	node_process = lib_common.gUriGen.PidUri(proc_obj.pid)

	try:
		# Old versions of psutil
		subprocs = proc_obj.get_children(recursive=False)
	except Exception:
		# From psutil 3.2.2 at least.
		subprocs = proc_obj.children(recursive=False)

	for child in subprocs:
		node_child = lib_common.gUriGen.PidUri(child.pid)
		grph.add( ( node_process, pc.property_ppid, node_child ) )
		AddExtraInformationtoProcess(grph,node_child,child)
		tree_subprocesses(grph, child)

# Recursively add links for the parent processes.
def tree_parent_process(grph, proc_obj):
	try:
		the_pid = proc_obj.pid
		if the_pid == 0 or the_pid == 1:
			return
		# Strange, but apparently it can happen.
		the_ppid = lib_entity_CIM_Process.PsutilProcToPPid(proc_obj)
		if the_ppid == 0:
			return

		if lib_common.UselessProc(proc_obj):
			return

		node_process = lib_common.gUriGen.PidUri(the_pid)
		node_pprocess = lib_common.gUriGen.PidUri(the_ppid)
		grph.add( ( node_pprocess, pc.property_ppid, node_process ) )
		lib_entity_CIM_Process.AddInfo( grph, node_pprocess, [ str(the_ppid) ] )

		AddExtraInformationtoProcess(grph,node_process,proc_obj)

		parent_proc_obj = psutil.Process(the_ppid)
		tree_parent_process( grph, parent_proc_obj )
	# This exception depends on the version of psutil.
	except lib_entity_CIM_Process.NoSuchProcess:
		# Maybe a process has suddenly disappeared. It does not matter.
		return

def Main():
	cgiEnv = lib_common.CgiEnv()
	try:
		root_pid = int(cgiEnv.GetId())
	except KeyError:
		lib_common.ErrorMessageHtml("Process id should be provided")

	grph = rdflib.Graph()

	proc_obj = lib_entity_CIM_Process.PsutilGetProcObj(root_pid)

	# Sub-processes, recursion.
	tree_subprocesses( grph, proc_obj )

	# Now display the parent processes.
	# It could be done in a loop instead of recursive calls.
	tree_parent_process( grph, proc_obj )

	# This layout style, because the nodes are quite big.
	cgiEnv.OutCgiRdf(grph, "LAYOUT_RECT")
	# cgiEnv.OutCgiRdf(grph)

if __name__ == '__main__':
	Main()

