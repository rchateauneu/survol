# This loads with rdflib a RDF/XML file.
# This checking its conformance.
import sys
import rdflib


def LoadRdfFile(filename):
    print("filename=", filename)
    g = rdflib.Graph()
    g.parse(filename)


    # Ajouter des requetes Sparql standards pour tester le concept d'analyse des dependances:
    # - Les sous-process.
    # - Les dependances des fichiers.
    # - Les commandes.

for oneFile in sys.argv[1:]:
    LoadRdfFile(oneFile)
