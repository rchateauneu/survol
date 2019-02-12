# This explores the classes of the WBEM server running on this machine
# and generates an OWL-DL ontology.

# It does not depend on a Survol installation.
# However, its classes and properties will overlap Survol's if it is installed.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

from __future__ import print_function
from rdflib.namespace import OWL, RDF, RDFS, XSD
from rdflib import Graph, Literal, Namespace, URIRef

import os
import sys

# Construct the linked data tools namespace
# See lib_properties.py: primns = "http://primhillcomputers.com/survol"
LDT = Namespace("http://www.primhillcomputers.com/survol#")

# Create the graph
graph = Graph()

onto_filnam = os.path.join(os.path.dirname(__file__), "WBEM_OWL_DL.owl")

outfil = open(onto_filnam,"w")
outfil.write( graph.serialize(format='pretty-xml') )
outfil.close()

sys.stderr.write("OK\n")
