#!/usr/bin/env python

"""Displays the WMI classes and attributes of this Windows machine."""

# This creates an RDFS ontology out of the WMI classes of a Windows machine.

# It does not depend on a Survol installation.
# However, its classes and properties will overlap Survol's if it is installed.
# Also, because they use rdflib and wmi, it is simpler to share the same code.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os

import lib_ontology_tools
import lib_export_ontology
import lib_kbase
import lib_wmi


def Main():
    # This extracts the WMI classes and attributes and translates them into RDF.
    map_classes, map_attributes = lib_ontology_tools.ManageLocalOntologyCache("wmi", lib_wmi.ExtractWmiOntologyLocal)
    graph = lib_kbase.CreateRdfsOntology(map_classes, map_attributes)

    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    lib_export_ontology.FlushOrSaveRdfGraph(graph,onto_filnam)


if __name__ == '__main__':
    Main()
