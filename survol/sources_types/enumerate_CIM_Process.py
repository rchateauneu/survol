#!/usr/bin/env python

"""
Processes tree
"""

import sys
import psutil
import lib_util
import lib_common
from sources_types import CIM_Process
from lib_properties import pc


def Main():
    paramkey_hide_user_accounts = "Hide user accounts"
    paramkey_show_command_line = "Show command line"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={
            paramkey_hide_user_accounts: False,
            paramkey_show_command_line: False}
    )

    flag_hide_user_accounts = bool(cgiEnv.get_parameters(paramkey_hide_user_accounts))
    flag_show_command_line = bool(cgiEnv.get_parameters(paramkey_show_command_line))

    grph = cgiEnv.GetGraph()

    # With a dictionary so node are created once only.
    # This attribute belongs to the function (defintion), and not to the function call.
    # Must be mindful of threading and recursion.

    Main.dict__pid_to_node = {}

    def _pid_to_node(the_pid):
        try:
            return Main.dict__pid_to_node[the_pid]
        except KeyError:
            node = lib_common.gUriGen.PidUri(the_pid)
            Main.dict__pid_to_node[the_pid] = node
            return node

    # Problem here: There is a second loopkup to get the name of the process.
    # In the mean time, the process might have disappeared.
    # Another problem due to Windows is that a parent process might have exit,
    # although it children processes are not reassigned (As it is the case on Unix).
    # This is a "non-existent process".
    for proc in psutil.process_iter():
        pid = proc.pid
        parent_pid = proc.ppid()

        # Built the same way in other RDF documents.
        node_process = _pid_to_node(pid)
        parent_node_process = _pid_to_node(parent_pid)

        # We avoid duplicating the edges. Why would the RDF merge do?
        grph.add((node_process, pc.property_ppid, parent_node_process))
        grph.add((node_process, pc.property_pid, lib_util.NodeLiteral(pid)))

        if not flag_hide_user_accounts:
            usr_nam = CIM_Process.PsutilProcToUser(proc, None)
            if usr_nam:
                # TODO: Maybe it would be more convenient to display the user as a simple string,
                # TODO: such as lib_util.NodeLiteral(usr_nam)
                user_node = lib_common.gUriGen.UserUri(usr_nam)
                grph.add((node_process, pc.property_user, user_node))

        if flag_show_command_line:
            cmd_line = CIM_Process.PsutilProcToCmdline(proc)
            if cmd_line and cmd_line != CIM_Process.ProcessAccessDenied:
                # TODO: The command line should be clickable.
                # TODO: ... but just display it as a string.
                # TODO: See CIM_Process.add_command_line_arguments
                node_cmd_line = lib_util.NodeLiteral(cmd_line)
                grph.add((node_process, pc.property_command, node_cmd_line))

        # TODO: Add the username as a property ? Change the color with the username ?
        # TODO: Get icons of users or programs, use their colors ?
        # TODO: Or get the graphic chart of any software related to a resource ?

    # TODO: It would be neat when displaying in SVG,
    # TODO: ... to specify that some nodes, when used as objects (not subjects),
    # TODO: ... should not have their own node but simply appear as an URL in the box of the subject.
    # TODO: This would simplify the network.
    # TODO: It would still be possible to display the object node, but without the connections.
    # TODO: Something like: isolated_classes=["LMI_Account"]
    # TODO: This could be a tunable parameter.
    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()
