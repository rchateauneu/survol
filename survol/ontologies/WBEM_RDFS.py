#!/usr/bin/env python

"""Displays the classes and attributes of the WBEM server."""

# This explores the classes of the WBEM server running on this machine
# and generates an RDFS ontology.

# It does not depend on a Survol installation.
# However, its classes and properties will overlap Survol's if it is installed.
# Also, because they use rdflib and wbem, it is simpler to share the same code.

import os
import sys
import rdflib
import lib_ontology_tools
import lib_export_ontology
import lib_wbem
import lib_common


def Main():
    # This extracts the classes and attributes of a WBEM server and translates them into RDF.
    try:
        graph = rdflib.Graph()
        lib_ontology_tools.serialize_ontology_to_graph("wbem", lib_wbem.extract_specific_ontology_wbem, graph)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    lib_export_ontology.flush_or_save_rdf_graph(graph, onto_filnam)


if __name__ == '__main__':
    Main()
