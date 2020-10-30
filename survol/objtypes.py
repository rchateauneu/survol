#!/usr/bin/env python

"""
Object types
Hierarchy of generic Survol ontology classes.
"""

import os
import sys

import lib_util
import lib_common
from lib_properties import pc

# TODO: Do not display classes as always prefixed by "Generic " such as "Generic class Win32_Product".
# In the __init__.py, tell if this is also a WMI or WBEM class, maybe add the namespace etc...

# TODO: Display a __doc__ with each class, by importing the module.


def Main():
    cgiEnv = lib_common.CgiEnv()

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    # This assumes that we have no namespace.
    for entity_type in lib_util.ObjectTypes():

        tmp_node = root_node
        idx = 0

        while idx >= 0:
            next_slash = entity_type.find("/", idx + 1)
            if next_slash == -1:
                intermed_type = entity_type
            else:
                intermed_type = entity_type[:next_slash]

            entity_node = lib_util.EntityClassNode(intermed_type)
            grph.add((tmp_node, pc.property_directory, entity_node))

            try:
                # This reloads all classes without cache because if it does not load
                # we want to see the error message.
                entity_module = lib_util.GetEntityModuleNoCatch(entity_type)
                ent_doc = entity_module.__doc__
            except Exception as exc:
                ent_doc = "Error:" + str(exc)

            if ent_doc:
                ent_doc = ent_doc.strip()
                grph.add((entity_node, pc.property_information, lib_util.NodeLiteral(ent_doc)))

            # TODO: If this is a CIM class, add WMI or WBEM documentation, or add the link.

            tmp_node = entity_node
            idx = next_slash

    cgiEnv.OutCgiRdf("LAYOUT_RECT")


if __name__ == '__main__':
    Main()
