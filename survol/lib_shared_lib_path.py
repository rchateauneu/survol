import os
import logging
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
    for one_dir in dirs:
        a_dir_lower = one_dir.lower()
        if a_dir_lower not in dirs_lower:
            dirs_lower.add(a_dir_lower)
            library_search_path.append(one_dir)

if lib_util.isPlatformLinux:
    library_search_path = os.environ["PATH"].split(':')


def FindPathFromSharedLibraryName(dll_filename):
    for a_dir in library_search_path:
        dll_path = os.path.join(a_dir, dll_filename)
        if os.path.exists(dll_path):
            logging.debug("FindPathFromSharedLibraryName dll_path=%s", dll_path)
            return dll_path
    logging.debug("FindPathFromSharedLibraryName cannot find dllFilename=%s", dll_filename)
    return None
