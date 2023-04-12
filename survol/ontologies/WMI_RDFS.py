#!/usr/bin/env python

"""Displays the WMI classes and attributes of this Windows machine."""

# This creates an RDFS ontology out of the WMI classes of a Windows machine.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os
import rdflib
import lib_ontology_tools
import lib_export_ontology
import lib_wmi
import lib_common

def Main():
    try:
        graph = rdflib.Graph()
        lib_ontology_tools.serialize_ontology_to_graph("wmi", lib_wmi.extract_specific_ontology_wmi, graph)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    lib_export_ontology.flush_or_save_rdf_graph(graph, onto_filnam)


if __name__ == '__main__':
    Main()
