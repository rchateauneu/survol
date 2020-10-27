import os
import sys

_is_py3 = sys.version_info >= (3,)
_is_windows = 'win32' in sys.platform

_standardized_file_path_cache = dict()


def standardized_file_path(file_path):
    """Cached of _standardized_file_path_nocache() which is slow and often called with the same file pathes. """
    global _standardized_file_path_cache
    try:
        return _standardized_file_path_cache[file_path]
    except KeyError:
        standard_path = _standardized_file_path_nocache(file_path)
        _standardized_file_path_cache[file_path] = standard_path
        return standard_path


# Windows has two specific details with file path:
# - They are case-insensitive but different utilities might change the case.
# - Backslashes can be difficult to handle.
# Therefore this function attempts to find the genuine case of a Windows file path,
# and replace backslashes by slashes.
#
# For example /usr/bin/python2.7
# Typical situation of symbolic links:
# /usr/bin/python => python2 => python2.7
#
# For example, this is needed because Sparql queries do not accept backslashes.
def _standardized_file_path_nocache(file_path):
    if _is_py3:
        if isinstance(file_path, bytes):
            file_path = file_path.decode()
    else:
        if isinstance(file_path, unicode):
            file_path = file_path.encode()
    assert isinstance(file_path, str)

    if _is_windows:
        # FIXME: Symbolic link on Windows ? Not used yet. Beware of this:
        # FIXME: os.path.realpath('c:') => 'C:\Users\the_current_user'

        # When running in PyCharm with virtualenv, the path is correct:
        # "C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/venv/Scripts/python.exe"
        # When running from pytest, it is converted to lowercase.
        # "c:/python27/python.exe" instead of "C:/Python27/python.exe"
        #
        # But it is not possible at this stage, to detect if we run in pytest,
        # because the environment variable 'PYTEST_CURRENT_TEST' is not set yet;
        # 'PYTEST_CURRENT_TEST': 'tests/test_client_library.py::SurvolLocalTest::test_process_cwd (call)'

        # If the file does not exist, cannot do anything.
        if os.path.isdir(file_path) or os.path.isfile(file_path):
            try:
                import win32api
                short_path = win32api.GetShortPathName(file_path)
                assert isinstance(short_path, str)
                file_path = win32api.GetLongPathName(short_path)
                assert isinstance(file_path, str)

            except ImportError:
                # Here we cannot do anything.

                # https://stackoverflow.com/questions/27465610/how-can-i-get-the-proper-capitalization-for-a-path
                # This is an undocumented function, for Python 3 only.
                # os.path._getfinalpathname("c:/python27/python.exe") => '\\\\?\\C:\\Python27\\python.exe'
                # os.path._getfinalpathname("c:/python27/python.exe").lstrip(r'\?') => 'C:\\Python27\\python.exe'
                sys.stderr.write(__file__ + " Cannot import win32api to fix file_path:%s\n" % file_path)
                try:
                    file_path = os.path._getfinalpathname(file_path).lstrip(r'\?')
                    assert isinstance(file_path, str)
                    sys.stderr.write(__file__ + " _getfinalpathname:%s\n" % file_path)
                except AttributeError:
                    sys.stderr.write(__file__ + " Cannot use _getfinalpathname:%s\n" % file_path)
            except Exception as exc:
                # pywintypes.error: (5, 'GetShortPathNameW', 'Access is denied.')
                sys.stderr.write(__file__ + " file_path:%s caught:%s\n" % (file_path, str(exc)))
                # Leave the file name as it is.
                pass
        else:
            # TODO: Ideally, this should rebuild the file path from the root.
            # TODO: A bit too complicated, for this usage.
            #print("DOES NOT EXIST:", file_path, type(file_path))
            pass

        # FIXME: The drive must be in uppercase too. WHY ??
        if len(file_path) > 1 and file_path[1] == ':':
            file_path = file_path[0].upper() + file_path[1:]
        # sys.stderr.write(__file__ + " Fixed sys.executable:%s\n" % CurrentExecutable)

        file_path = file_path.replace("\\","/")
        #print(__file__ + " file_path=", file_path)
    else:
        # Eliminates symbolic links.
        file_path = os.path.realpath(file_path)
    assert isinstance(file_path, str)
    return file_path


def standardized_memmap_path(memmap_path):
    memmap_path = memmap_path.strip()
    # This could be "[anon]", "[heap]" etc...
    if not _is_windows and memmap_path.startswith("["):
        return memmap_path
    # This is a plain file path.
    return standardized_file_path(memmap_path)


