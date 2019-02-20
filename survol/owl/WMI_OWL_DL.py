# This creates a OWL-DL ontology out of the WMI classes of a Windows machine.

# It does not depend on a Survol installation.
# However, its classes and properties will overlap Survol's if it is installed.
# Also, because they use rdflib and wmi, it is simpler to share the same code.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os

import lib_export_ontology
import lib_util
import lib_wmi

def Main():
    map_classes, map_attributes = lib_wmi.ExtractWmiOntology()
    graph = lib_export_ontology.CreateOwlDlOntology(map_classes, map_attributes)

    onto_filnam = os.path.splitext(__file__)[0] + ".owl"
    out_dest = lib_util.DfltOutDest()
    lib_export_ontology.DumpOntology(graph,onto_filnam,out_dest)

if __name__ == '__main__':
    Main()
