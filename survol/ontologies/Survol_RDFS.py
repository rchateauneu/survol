#!/usr/bin/env python

"""This creates a RDFS ontology out of the Survol classes."""

# It is part of a survol installation.
# However, its classes and properties overlaps the ones created by WMI or WBEM.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os
import rdflib

import lib_export_ontology
import lib_ontology_tools
import lib_common
import lib_util


def Main():
    try:
        graph = rdflib.Graph()
        lib_ontology_tools.serialize_ontology_to_graph("survol", lib_util.extract_specific_ontology_survol, graph)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    # "Survol_RDFS_DL.rdfs"
    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    lib_export_ontology.flush_or_save_rdf_graph(graph, onto_filnam)


if __name__ == '__main__':
    Main()
