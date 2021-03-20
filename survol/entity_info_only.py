#!/usr/bin/env python

"""
Overview
"""

import os
import re
import sys
import logging
import lib_kbase
import lib_util
import lib_common
from lib_properties import pc


# We want only literal information which can be displayed in a table.
def AddInformation(grph, root_node, entity_id, entity_type):
    entity_ids_arr = lib_util.EntityIdToArray(entity_type, entity_id)

    # Each entity type ("process","file" etc... ) can have a small library
    # of its own, for displaying a rdf node of this type.
    if entity_type:
        entity_module = lib_util.GetEntityModule(entity_type)
        if entity_module:
            try:
                # On text information are kept. This must be very fast.
                class FilterLiteralRdfGraph:
                    # Init with a genuine rdflib graph.
                    def __init__(self,grph,destNode):
                        self.m_grph = grph
                        self.m_node = destNode

                    # If the information is not a literal, we could display the associated name.
                    # Also, consider recursive tables.
                    def _filter_subject_object(self, subj_rdf, obj_rdf):
                        return (subj_rdf == self.m_node) and lib_kbase.IsLiteral(obj_rdf)

                    # This filters only literal properties which points to or from our node.
                    # This also ensures that there is one node only, no links, because json documents generation.
                    # THE WHOLE SCRIPT MUST BE REPLACED BY A REAL JSON DOCUMENT, TRANSFORMED INTO HTML.
                    def add(self, trpl):
                        if self._filter_subject_object(trpl[0], trpl[2]):
                            self.m_grph.add(trpl)
                        if self._filter_subject_object(trpl[2], trpl[0]):
                            self.m_grph.add((trpl[2], trpl[1], trpl[0]))

                pseudo_graph = FilterLiteralRdfGraph(grph, root_node)

                entity_module.AddInfo(pseudo_graph, root_node, entity_ids_arr)

            except AttributeError as exc:
                logging.error("No AddInfo for %s %s: %s", entity_type, entity_id, str(exc) )
    else:
        logging.warning("No lib_entities for %s %s", entity_type, entity_id)


def Main():
    # This can process remote hosts because it does not call any script, just shows them.
    cgiEnv = lib_common.ScriptEnvironment(can_process_remote=True)
    entity_id = cgiEnv.m_entity_id

    name_space, entity_type = cgiEnv.get_namespace_type()

    grph = cgiEnv.GetGraph()

    root_node = lib_util.RootUri()

    AddInformation(grph, root_node, entity_id, entity_type)

    cgiEnv.OutCgiRdf()

if __name__ == '__main__':
    Main()

