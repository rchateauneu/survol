#!/usr/bin/python

"""
Top-level windows
"""

import sys
import socket
import rdflib
import psutil
import lib_common
import lib_util
from lib_properties import pc
from sources_types import Win32_Window
from sources_types import CIM_Process

#import win32api
#import win32con
import win32gui
import win32process

# Necessary otherwise it is displayed on Linux machines,
# as it does not import any Windows-specific module.
Usable = lib_util.UsableWindows

def windowEnumerationHandler(hwnd, topWindowsHnd):
	if win32gui.IsWindowVisible(hwnd):
		topWindowsHnd.append(hwnd)

def Main():
	cgiEnv = lib_common.CgiEnv()

	grph = rdflib.Graph()

	rootNode = lib_common.nodeMachine

	topWindowsHnd = []
	win32gui.EnumWindows(windowEnumerationHandler, topWindowsHnd)

	sys.stdout.write("Len=%d\n"%len(topWindowsHnd))

	# for hwnd in topWindowsHnd:
	# 	wnText = win32gui.GetWindowText(hwnd)
	# 	thrId, procId = win32process.GetWindowThreadProcessId(hwnd)
	# 	sys.stdout.write("id=%d %s \n"%(procId,wnText))
	#
	# 	nodeWindow = Win32_Window.MakeUri()
	#
	# 	grph.add( (nodeWindow, pc.property_information, rdflib.Literal(winProd.InstalledProductName) ) )
	# 	grph.add( (productNode, propWin32Version, nodeWindow ) )
	#
	# 	grph.add( ( lib_common.nodeMachine, propWin32Product, productNode ) )
	#
	# except:
	# 	exc = sys.exc_info()[1]
	# 	lib_common.ErrorMessageHtml("Caught:%s"%str(exc))


	cgiEnv.OutCgiRdf(grph )

if __name__ == '__main__':
	Main()

