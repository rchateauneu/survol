import sys

import win32api
import win32con
import win32gui
import win32process

# We are going to use the win32gui.EnumWindows() function to get our top level window information.
# This is one of those nasty functions which wants a callback function passed to it (consult the docs if you are really bored).
# So here's one I made earlier:

def windowEnumerationHandler(hwnd, topWindowsHnd):
	if win32gui.IsWindowVisible(hwnd):
		topWindowsHnd.append(hwnd)



# We can pass this, along a list to hold the results, into win32gui.EnumWindows(), as so:

topWindowsHnd = []

win32gui.EnumWindows(windowEnumerationHandler, topWindowsHnd)

sys.stdout.write("Len=%d\n"%len(topWindowsHnd))

for hwnd in topWindowsHnd:
	wnText = win32gui.GetWindowText(hwnd)
	thrId, procId = win32process.GetWindowThreadProcessId(hwnd)
	sys.stdout.write("id=%d %s \n"%(procId,wnText))

