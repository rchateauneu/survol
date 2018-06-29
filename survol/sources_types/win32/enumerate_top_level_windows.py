#!/usr/bin/python

"""
Top-level windows
"""

import sys
import socket
import lib_common
import lib_util
from lib_properties import pc
from sources_types import CIM_Process

import win32gui
import win32process

def windowEnumerationHandler(hwnd, topWindowsHnd):
	if win32gui.IsWindowVisible(hwnd):
		topWindowsHnd.append(hwnd)

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = cgiEnv.GetGraph()

	rootNode = lib_common.nodeMachine

	topWindowsHnd = []
	win32gui.EnumWindows(windowEnumerationHandler, topWindowsHnd)

	prpProcToWindow = lib_common.MakeProp("Top_level_window")

	def PidToNode(pid):
		try:
			nodPid = PidToNode.Cache[pid]
		except KeyError:
			nodPid = lib_common.gUriGen.PidUri(pid)
			PidToNode.Cache[pid] = nodPid

			grph.add( (nodPid, pc.property_pid, lib_common.NodeLiteral(pid) ) )
			grph.add( (rootNode, pc.property_host, nodPid ) )

		return nodPid

	PidToNode.Cache = dict()


	sys.stdout.write("Len=%d\n"%len(topWindowsHnd))

	for hwnd in topWindowsHnd:
		wnText = win32gui.GetWindowText(hwnd)
		thrId, procId = win32process.GetWindowThreadProcessId(hwnd)
		nodProcess = PidToNode(procId)
		sys.stderr.write("procId=%d wnText=%s\n"%(procId,wnText))
		if wnText:
			# wnText = wnText.encode("ascii" ,errors='replace')
			# It drops the accent: "Livres, BD, Vidos"
			try:
				# Python 3: "AttributeError: 'str' object has no attribute 'decode' "
				wnText = wnText.decode("utf8" ,'ignore')
			except:
				# If Python 3, nothing to do>
				pass
			grph.add( (nodProcess, prpProcToWindow, lib_common.NodeLiteral(wnText) ) )

	cgiEnv.OutCgiRdf("LAYOUT_RECT", [prpProcToWindow])

if __name__ == '__main__':
	Main()

