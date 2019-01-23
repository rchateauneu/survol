import os
import lib_util

# This returns the full path name of a shared library file name.
# This works in similar ways on Windows on Linux.
# The difference is in the PATH.

# This is done only once because it should not change in a process lifetime.

if lib_util.isPlatformWindows:
	import win32api
	library_search_path = []
	path = win32api.GetEnvironmentVariable('PATH')

	# try paths as described in MSDN
	dirs = [os.getcwd(), win32api.GetSystemDirectory(), win32api.GetWindowsDirectory()] + path.split(';')

	dirs_lower = set()
	for aDir in dirs:
		aDirLower = aDir.lower()
		if aDirLower not in dirs_lower:
			dirs_lower.add(aDirLower)
			library_search_path.append(aDir)

if lib_util.isPlatformLinux:
	library_search_path = os.environ["PATH"].split(':')

def FindPathFromSharedLibraryName(dllFilename):
	for aDir in library_search_path:
		dllPath = os.path.join(aDir, dllFilename)
		if os.path.exists(dllPath):
			DEBUG("FindPathFromSharedLibraryName dllPath=%s",dllPath)
			return dllPath
	DEBUG("FindPathFromSharedLibraryName cannot find dllFilename=%s",dllFilename)
	return None
