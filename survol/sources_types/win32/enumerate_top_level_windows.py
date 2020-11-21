#!/usr/bin/env python

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


def _window_enumeration_handler(hwnd, top_windows_hnd):
    if win32gui.IsWindowVisible(hwnd):
        top_windows_hnd.append(hwnd)


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    root_node = lib_common.nodeMachine

    top_windows_hnd = []
    win32gui.EnumWindows(_window_enumeration_handler, top_windows_hnd)

    prp_proc_to_window = lib_common.MakeProp("Top_level_window")

    def pid_to_node(pid):
        try:
            nod_pid = pid_to_node.Cache[pid]
        except KeyError:
            nod_pid = lib_common.gUriGen.PidUri(pid)
            pid_to_node.Cache[pid] = nod_pid

            grph.add((nod_pid, pc.property_pid, lib_util.NodeLiteral(pid)))
            grph.add((root_node, pc.property_host, nod_pid))

        return nod_pid

    pid_to_node.Cache = dict()

    for hwnd in top_windows_hnd:
        wn_text = win32gui.GetWindowText(hwnd)
        thr_id, proc_id = win32process.GetWindowThreadProcessId(hwnd)
        nod_process = pid_to_node(proc_id)
        DEBUG("proc_id=%d wn_text=%s",proc_id,wn_text)
        if wn_text:
            # wn_text = wn_text.encode("ascii" ,errors='replace')
            # It drops the accent: "Livres, BD, Vidos"
            try:
                # Python 3: "AttributeError: 'str' object has no attribute 'decode' "
                wn_text = wn_text.decode("utf8", 'ignore')
            except:
                # If Python 3, nothing to do>
                pass
            grph.add((nod_process, prp_proc_to_window, lib_util.NodeLiteral(wn_text)))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", [prp_proc_to_window])


if __name__ == '__main__':
    Main()

