import rdflib
from rdflib.graph import Graph, ConjunctiveGraph
from rdflib import Graph, URIRef, BNode, Literal
from rdflib import Namespace
from rdflib.namespace import OWL, RDF, RDFS, FOAF

# https://lov.linkeddata.es/dataset/lov/about
# https://lov.linkeddata.es/Recommendations_Vocabulary_Design.pdf

if False:
    myOntology =  Namespace("http://www.semanticweb.org/myOntology#")
    g.bind("myOntology", myOntology)

    # Create the graph
    g = Graph()
    # Create the node to add to the Graph
    urbanSystem = URIRef(myOntology["urbanSystem"])

    # Add the OWL data to the graph
    g.add((urbanSystem, RDF.type, OWL.Class))
    g.add((urbanSystem, RDFS.subClassOf, OWL.Thing))

    name = URIRef(myOntology["name"])
    g.add((name, RDF.type, OWL.Class))
    g.add((name, RDFS.subClassOf, urbanSystem))


def add_ontology_metadata(rdf_graph):
    """
    This adds metadata as specified by https://lov.linkeddata.es/Recommendations_Vocabulary_Design.pdf ,
    so this ontology can be inserted into LOV (Linked Open Data Vocabularies)
    :param rdf_graph:
    :return:
    """
    pass


