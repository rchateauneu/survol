#!/usr/bin/env python

import os
import sys
import rdflib
import time
import logging

import lib_kbase
import lib_util
import lib_common
import lib_properties
from lib_properties import pc
from sources_types import CIM_Directory

# http://timgolden.me.uk/python/win32_how_do_i/watch_directory_for_changes.html#use_findfirstchange

import win32file
import win32con


def Usable(entity_type, entity_ids_arr):
    """Can run on a directory only, on Windows."""
    if not lib_util.UsableWindows(entity_type, entity_ids_arr):
        return False
    dir_nam = entity_ids_arr[0]
    return os.path.isdir(dir_nam)


property_notified_file_change = lib_properties.MakeProp("file change")
property_notified_change_type = lib_properties.MakeProp("change type")


def _add_windows_dir_change(grph, path_to_watch, updated_file, action_code, timestamp_node):
    actions_codes = {
        1: "Created",
        2: "Deleted",
        3: "Updated",
        4: "Renamed from something",
        5: "Renamed to something"
    }

    action_text = actions_codes.get(action_code, "Unknown")
    full_filename = os.path.join(path_to_watch, updated_file)

    node_path = lib_common.gUriGen.FileUri(full_filename)

    sample_root_node = rdflib.BNode()
    grph.add((node_path, property_notified_file_change, sample_root_node))

    # FIXME: Use lib_kbase.time_tsamp_now_node()
    grph.add((sample_root_node, pc.property_information, timestamp_node))
    grph.add((sample_root_node, property_notified_change_type, lib_util.NodeLiteral(action_text)))

    # TODO: How to detect which process has updated the file ?
    # TODO: Consider lsof on Linux.
    # TODO: Use the same property as dockit detection of file accesses.
    # TODO: Add a new triplet with the process id doing the change, or change the semantics.


# Thanks to Claudio Grondi for the correct set of numbers
FILE_LIST_DIRECTORY = 0x0001


def Snapshot():
    cgiEnv = lib_common.CgiEnv()
    path_to_watch = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()
    directory_node = lib_common.gUriGen.DirectoryUri(path_to_watch)
    CIM_Directory.AddInfo(grph, directory_node, [path_to_watch],)

    cgiEnv.OutCgiRdf()


def send_events_once():
    cgiEnv = lib_common.CgiEnv()
    path_to_watch = cgiEnv.GetId()

    h_dir = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
    )

    while True:
        # Not too fast.
        time.sleep(5)
        grph = cgiEnv.ReinitGraph()

        #
        # ReadDirectoryChangesW takes a previously-created handle to a directory, a buffer size for results,
        # a flag to indicate whether to watch subtrees and a filter of what changes to notify.
        #
        # NB Tim Juchcinski reports that he needed to up the buffer size to be sure of picking up all
        # events when a large number of files were deleted at once.
        #
        # TODO: Use asynchronous completion ?
        # https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw
        # https://stackoverflow.com/questions/49799109/win32file-readdirectorychangesw-doesnt-find-all-moved-files

        results = win32file.ReadDirectoryChangesW(
            h_dir,
            65536,
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

        timestamp_node = lib_kbase.time_stamp_now_node()
        for action_code, updated_file in results:
            _add_windows_dir_change(grph, path_to_watch, updated_file, action_code, timestamp_node)

        cgiEnv.OutCgiRdf("LAYOUT_RECT", [property_notified_file_change])


def Main():
    sys.stderr.write(__file__ + "\n")
    if lib_util.is_snapshot_behaviour():
        Snapshot()
    else:
        while True:
            try:
                send_events_once()
            except Exception as exc:
                sys.stderr.write(__file__ + " caught: %s" % exc)
                logging.warning("caught: %s\n" % exc)


if __name__ == '__main__':
    Main()
