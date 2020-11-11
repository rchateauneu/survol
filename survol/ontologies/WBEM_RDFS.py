#!/usr/bin/env python

"""Displays the classes and attributes of the WBEM server."""

# This explores the classes of the WBEM server running on this machine
# and generates an RDFS ontology.

# It does not depend on a Survol installation.
# However, its classes and properties will overlap Survol's if it is installed.
# Also, because they use rdflib and wbem, it is simpler to share the same code.

import os
import sys
import lib_ontology_tools
import lib_export_ontology
import lib_kbase
import lib_wbem
import lib_common


def Main():
    # This extracts the classes and attributes of a WBEM server and translates them into RDF.
    try:
        map_classes, map_attributes = lib_ontology_tools.ManageLocalOntologyCache("wbem", lib_wbem.ExtractWbemOntology)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    graph = lib_kbase.CreateRdfsOntology(map_classes, map_attributes)

    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    lib_export_ontology.FlushOrSaveRdfGraph(graph, onto_filnam)


if __name__ == '__main__':
    Main()
