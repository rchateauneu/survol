#!/usr/bin/env python

"""
Overview
"""

import os
import re
import sys
import logging
import lib_util
import lib_common
from lib_properties import pc

def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    entity_id = cgiEnv.m_entity_id

    name_space, entity_type = cgiEnv.get_namespace_type()

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)

    mode_disp = lib_util.GuessDisplayMode()
    logging.debug("entity_mime.py entity_type=%s mode_disp=%s", entity_type, mode_disp)

    if not entity_type:
        lib_common.ErrorMessageHtml("entity_mime.py needs an object")

    entity_module = lib_util.GetEntityModule(entity_type)
    if not entity_module:
        lib_common.ErrorMessageHtml("entity_mime.py entity_type=%s needs a module" % entity_type)

    try:
        entity_module.DisplayAsMime(grph, root_node, entity_ids_arr)
    except Exception as exc:
        lib_common.ErrorMessageHtml(
            __file__ + " DisplayAsMime fails: %s %s: %s. File=%s.\n"
            % (entity_type, entity_id, str(exc), entity_module.__file__))


if __name__ == '__main__':
    Main()

