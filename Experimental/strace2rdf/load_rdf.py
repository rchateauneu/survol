# This loads with rdflib a RDF/XML file.
# This checking its conformance.
import sys
import rdflib


def LoadRdfFile(filename):
    print("filename=", filename)
    g = rdflib.Graph()
    g.parse(filename)

for oneFile in sys.argv[1:]:
    LoadRdfFile(oneFile)
