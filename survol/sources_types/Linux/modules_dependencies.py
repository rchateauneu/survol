#!/usr/bin/env python

"""
Linux modules dependencies
"""

import sys
import socket

import lib_common
import lib_util
import lib_modules
from lib_properties import pc

#
# The modules.dep as generated by module-init-tools depmod,
# lists the dependencies for every module in the directories
# under /lib/modules/version, where modules.dep is. 
#
# cat /proc/version
# Linux version 2.6.24.7-desktop586-2mnb (qateam@titan.mandriva.com) (gcc version 4.2.3 (4.2.3-6mnb1)) #1 SMP Thu Oct 30 17:39:28 EDT 2008
# ls /lib/modules/$(cat /proc/version | cut -d " " -f3)/modules.dep
#
# /lib/modules/2.6.24.7-desktop586-2mnb/modules.dep
# /lib/modules/2.6.24.7-desktop586-2mnb/dkms-binary/drivers/char/hsfmc97via.ko.gz: /lib/modules/2.6.24.7-desktop586-2mnb/dkms-binary/drivers/char/hsfserial.ko.gz /lib/modules/2.6.24.7-desktop586-2mnb/dkms-binary/drivers/char/hsfengine.ko.gz /lib/modules/2.6.24.7-desktop586-2mnb/dkms-binary/drivers/char/hsfosspec.ko.gz /lib/modules/2.6.24.7-desktop586-2mnb/kernel/drivers/usb/core/usbcore.ko.gz /lib/modules/2.6.24.7-desktop586-2mnb/dkms-binary/drivers/char/hsfsoar.ko.gz
#
#


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    grph = cgiEnv.GetGraph()

    # TODO: The dependency network is huge, so we put a limit, for the moment.
    max_cnt = 0

    try:
        modudeps = lib_modules.Dependencies()
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:"+str(exc))

    for module_name in modudeps:
        # NOT TOO MUCH NODES: BEYOND THIS, IT IS FAR TOO SLOW, UNUSABLE. HARDCODE_LIMIT
        max_cnt += 1
        if max_cnt > 2000:
            logging.error("Too many modules to display. Break.")
            break

        file_parent = lib_modules.ModuleToNode(module_name)
        file_child = None
        for module_dep in modudeps[module_name]:

            # print ( module_name + " => " + module_dep )

            # This generates a directed acyclic graph,
            # but not a tree in the general case.
            file_child = lib_modules.ModuleToNode(module_dep)

            grph.add((file_parent, pc.property_module_dep, file_child))
        # TODO: Ugly trick, otherwise nodes without connections are not displayed.
        # TODO: I think this is a BUG in the dot file generation. Or in RDF ?...
        if file_child is None:
            grph.add((file_parent, pc.property_information, lib_util.NodeLiteral("")))

    # Splines are rather slow.
    if max_cnt > 100:
        layout_type = "LAYOUT_XXX"
    else:
        layout_type = "LAYOUT_SPLINE"
    cgiEnv.OutCgiRdf(layout_type)


if __name__ == '__main__':
    Main()
