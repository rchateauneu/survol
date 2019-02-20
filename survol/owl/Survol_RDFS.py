# This creates a OWL-DL ontology out of the Survol classes.
# It is part of a survol installation.
# However, its classes and properties overlaps the ones created by WMI or WBEM.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os
import lib_export_ontology
import lib_util

def Main():
    map_classes, map_attributes = lib_util.DumpSurvolOntology()
    graph = lib_export_ontology.CreateRdfsOntology(map_classes, map_attributes)

    # "Survol_OWL_DL.owl"
    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    out_dest = lib_util.DfltOutDest()
    lib_export_ontology.DumpOntology(graph,onto_filnam,out_dest)

if __name__ == '__main__':
    Main()
