#
# PyDBG
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# $Id: system_dll.py 238 2010-04-05 20:40:46Z rgovostes $
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

from __future__ import print_function

import os.path

from .windows_h import *

# macos compatability.
try:
    kernel32 = windll.kernel32
    psapi    = windll.psapi
except:
    kernel32 = CDLL(os.path.join(os.path.dirname(__file__), "libmacdll.dylib"))
    psapi    = kernel32

from .pdx import *

import os

import ctypes
from ctypes import wintypes

####################################################################################################################

LPSTR = POINTER(CHAR)

GetMappedFileNameA = ctypes.windll.psapi.GetMappedFileNameA
GetMappedFileNameA.argtypes = (wintypes.HANDLE, wintypes.LPVOID, LPSTR, wintypes.DWORD)
GetMappedFileNameA.restype = wintypes.BOOL
#  HANDLE hProcess,
#  LPVOID lpv,
#  LPSTR  lpFilename,
#  DWORD  nSize

CreateFileMappingA = ctypes.windll.kernel32.CreateFileMappingA
CreateFileMappingA.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, LPSTR)
CreateFileMappingA.restype = wintypes.HANDLE
#HANDLE CreateFileMappingA(
#  HANDLE                hFile,
#  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
#  DWORD                 flProtect,
#  DWORD                 dwMaximumSizeHigh,
#  DWORD                 dwMaximumSizeLow,
#  LPCSTR                lpName
#);

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.restype = wintypes.HANDLE

OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
OpenProcessToken.restype = wintypes.BOOL

IsWow64Process = ctypes.windll.kernel32.IsWow64Process
IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
IsWow64Process.restype = wintypes.BOOL

GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
GetCurrentProcess.argtypes = []
GetCurrentProcess.restype = wintypes.BOOL

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, c_size_t, POINTER(c_size_t)]

VirtualProtectEx = ctypes.windll.kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = [wintypes.HANDLE, LPVOID, c_size_t, wintypes.DWORD, POINTER(wintypes.DWORD)]
VirtualProtectEx.restype = wintypes.BOOL
# BOOL VirtualProtectEx(
#   HANDLE hProcess,
#   LPVOID lpAddress,
#   SIZE_T dwSize,
#   DWORD  flNewProtect,
#   PDWORD lpflOldProtect
# );

Module32First = ctypes.windll.kernel32.Module32First
Module32First.argtypes = (wintypes.HANDLE, POINTER(MODULEENTRY32))
Module32First.restype = wintypes.BOOL

OpenThread = ctypes.windll.kernel32.OpenThread
OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenThread.restype = HANDLE

OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
OpenProcessToken.restype = wintypes.BOOL

####################################################################################################################

class system_dll:
    '''
    System DLL descriptor object, used to keep track of loaded system DLLs and locations.

    @todo: Add PE parsing support.
    '''

    handle = None
    base   = None
    name   = None
    path   = None
    pe     = None
    size   = 0

    ####################################################################################################################
    def __init__ (self, handle, base):
        '''
        Given a handle and base address of the loaded DLL, determine the DLL name and size to fully initialize the
        system DLL object.
        Consider using GetFinalPathNameByHandleA() which does the same, since Windows Vista.
        https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlea

        @type  handle: HANDLE
        @param handle: Handle to the loaded DLL
        @type  base:   DWORD
        @param base:   Loaded address of DLL

        @raise pdx: An exception is raised on failure.
        '''

        self.handle = handle
        self.base   = base
        self.name   = None
        self.path   = None
        self.pe     = None
        self.size   = 0
        # self._log = lambda msg: None #sys.stderr.write("PDBG_LOG> " + msg + "\n")
        self._log = lambda msg: sys.stdout.write("PDBG_LOG> " + msg + "\n")

        # calculate the file size of the
        file_size_hi = c_ulong(0)
        #file_size_lo = 0
        file_size_lo = kernel32.GetFileSize(handle, byref(file_size_hi))
        self.size    = (file_size_hi.value << 8) + file_size_lo

        # create a file mapping from the dll handle.
        # CreateFileMappingA.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, LPSTR)
        file_map = kernel32.CreateFileMappingA(handle, c_void_p(0), c_ulong(PAGE_READONLY), c_ulong(0), c_ulong(1), b"")

        if file_map:
            # map a single byte of the dll into memory so we can query for the file name.
            kernel32.MapViewOfFile.restype = POINTER(c_char)
            file_ptr = kernel32.MapViewOfFile(file_map, FILE_MAP_READ, 0, 0, 1)

            if file_ptr:
                # query for the filename of the mapped file.
                filename = create_string_buffer(2048)
                psapi.GetMappedFileNameA(kernel32.GetCurrentProcess(), file_ptr, filename, c_ulong(2048))

                # store the full path. this is kind of ghetto, but i didn't want to mess with QueryDosDevice() etc ...
                self.path = b"\\" + filename.value.split(b"\\", 3)[3]
                #self._log("system_dll __init__ GetMappedFileNameA self.path=%s size=%d" % (self.path, self.size))

                # store the file name.
                # XXX - this really shouldn't be failing. but i've seen it happen.
                try:
                    self.name = filename.value[filename.value.rindex(os.sep)+1:]
                except:
                    self.name = self.path

                kernel32.UnmapViewOfFile(file_ptr)

            kernel32.CloseHandle(file_map)

        # self._log("system_dll __init__ leaving")

    ####################################################################################################################
    def __del__ (self):
        '''
        Close the handle.
        '''

        if kernel32:
            # Without the test, error message:
            # Exception AttributeError: "'NoneType' object has no attribute 'CloseHandle'"
            # in <bound method system_dll.__del__ of
            # <survol.scripts.pydbg.system_dll.system_dll instance at 0x0000000004116108>> ignored
            kernel32.CloseHandle(self.handle)