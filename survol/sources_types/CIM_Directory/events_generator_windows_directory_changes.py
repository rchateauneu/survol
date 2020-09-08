#!/usr/bin/env python

import os
import re
import sys
import lib_util
import lib_common
from lib_properties import pc

# http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html#use_findfirstchange

import win32file
import win32con


def Usable(entity_type, entity_ids_arr):
    """Can run on a directory only, on Windows."""
    if not lib_util.UsableWindows(entity_type,entity_ids_arr):
        return False
    if not lib_util.UsableAsynchronousSource(entity_type,entity_ids_arr):
        return False
    dir_nam = entity_ids_arr[0]
    return os.path.isdir(dir_nam)


def _add_windows_dir_change(grph, path_to_watch, updated_file, path_change):
    full_filename = os.path.join(path_to_watch, updated_file)

    split_path = file.split('\\')
    intermediate_path = path_to_watch

    intermediate_node = lib_common.gUriGen.FileUri( intermediate_path )

    for subdir in split_path[1:-1]:
        subpath = intermediate_path + "\\" + subdir
        sub_node = lib_common.gUriGen.FileUri( subpath )
        grph.add( ( intermediate_node, pc.property_directory, sub_node ) )
        intermediate_path = subpath
        intermediate_node = sub_node

    # TODO: Maybe show the intermediate first between this one and the script argument,
    # IF THIS IS NOT ALREADY DONE ?
    node_path = lib_common.gUriGen.FileUri( full_filename )
    grph.add( ( intermediate_node, pc.property_directory, node_path ) )

    grph.add( ( node_path, pc.property_notified_file_change, lib_common.NodeLiteral(path_change) ) )


ACTIONS = {
    1 : "Created",
    2 : "Deleted",
    3 : "Updated",
    4 : "Renamed from something",
    5 : "Renamed to something"
}

# Thanks to Claudio Grondi for the correct set of numbers
FILE_LIST_DIRECTORY = 0x0001

def Main():
    cgiEnv = lib_common.CgiEnv()
    path_to_watch = cgiEnv.GetId()

    hDir = win32file.CreateFile (
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while True:
        grph = cgiEnv.ReinitGraph()

        #
        # ReadDirectoryChangesW takes a previously-created
        # handle to a directory, a buffer size for results,
        # a flag to indicate whether to watch subtrees and
        # a filter of what changes to notify.
        #
        # NB Tim Juchcinski reports that he needed to up
        # the buffer size to be sure of picking up all
        # events when a large number of files were
        # deleted at once.
        #
        results = win32file.ReadDirectoryChangesW (
            hDir,
            1024,
            True,
            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
             win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
             win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
             win32con.FILE_NOTIFY_CHANGE_SIZE |
             win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
             win32con.FILE_NOTIFY_CHANGE_SECURITY,
            None,
            None
        )
        for action, updated_file in results:
            _add_windows_dir_change(grph, path_to_watch, updated_file, ACTIONS.get (action, "Unknown"))

        cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    if lib_util.is_snapshot_behaviour():
        Main()
    else:
        while True:
            Main(1000000)
