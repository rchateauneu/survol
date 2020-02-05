import pydbg

class HookManager:
    def __init__(self):
        self.hooks = pydbg.tests.utils.hook_container()

    def define_function(self, api_definition):
        return
        function_name = b"WriteFile"
        hook_address = tst_pydbg.func_resolve(b"kernel32.dll", function_name)
        assert hook_address

        def hook_function():
            pass
        self.hooks.add(tst_pydbg, hook_address, 5, hook_function, None)


hooks_manager = HookManager()

hooks_manager.define_function("""
BOOL WriteFile(
HANDLE       hFile,
LPCVOID      lpBuffer,
DWORD        nNumberOfBytesToWrite,
LPDWORD      lpNumberOfBytesWritten,
LPOVERLAPPED lpOverlapped
);""")
hooks_manager.define_function("""
BOOL WriteFileEx(
"HANDLE                          hFile,
"LPCVOID                         lpBuffer,
"DWORD                           nNumberOfBytesToWrite,
"LPOVERLAPPED                    lpOverlapped,
"LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);""")
hooks_manager.define_function("""
BOOL WriteFileGather(
  HANDLE                  hFile,
  FILE_SEGMENT_ELEMENT [] aSegmentArray,
  DWORD                   nNumberOfBytesToWrite,
  LPDWORD                 lpReserved,
  LPOVERLAPPED            lpOverlapped
);""")
hooks_manager.define_function("""
BOOL ReadFile(
  HANDLE       hFile,
  LPVOID       lpBuffer,
  DWORD        nNumberOfBytesToRead,
  LPDWORD      lpNumberOfBytesRead,
  LPOVERLAPPED lpOverlapped
);""")
hooks_manager.define_function("""
BOOL ReadFileEx(
  HANDLE                          hFile,
  LPVOID                          lpBuffer,
  DWORD                           nNumberOfBytesToRead,
  LPOVERLAPPED                    lpOverlapped,
  LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);""")
hooks_manager.define_function("""
BOOL ReadFileScatter(
  HANDLE                  hFile,
  FILE_SEGMENT_ELEMENT [] aSegmentArray,
  DWORD                   nNumberOfBytesToRead,
  LPDWORD                 lpReserved,
  LPOVERLAPPED            lpOverlapped
);""")
hooks_manager.define_function("""
BOOL CreateDirectoryA(
  LPCSTR                lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);""")
hooks_manager.define_function("""
BOOL RemoveDirectoryA(
  LPCSTR lpPathName
);""")
hooks_manager.define_function("""
BOOL RemoveDirectoryW(
  LPCWSTR lpPathName
);""")
hooks_manager.define_function("""
HANDLE CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);""")
hooks_manager.define_function("""
HANDLE CreateFileW(
  LPCWSTR               lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);""")
hooks_manager.define_function("""
BOOL DeleteFileA(
  LPCSTR lpFileName
);""")
hooks_manager.define_function("""
BOOL DeleteFileW(
  LPCWSTR lpFileName
);""")
hooks_manager.define_function("""
HANDLE CreateFile2(
  LPCWSTR                           lpFileName,
  DWORD                             dwDesiredAccess,
  DWORD                             dwShareMode,
  DWORD                             dwCreationDisposition,
  LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
);""")

