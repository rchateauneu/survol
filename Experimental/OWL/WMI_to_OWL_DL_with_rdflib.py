# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

from rdflib.namespace import OWL, RDF, RDFS, XSD
from rdflib import Graph, Literal, Namespace, URIRef

# Construct the linked data tools namespace
LDT = Namespace("http://www.primhillcomputers.com/survol#")

# Create the graph
graph = Graph()

# Create the node to add to the Graph
MyClassNode = URIRef(LDT["MyClass"])
MyBaseClassNode = URIRef(LDT["MyBaseClass"])

# Add the OWL data to the graph
# <OWL:Class rdf:ID="Service">
# <rdfs:subClassOf rdf:resource="#System"/>
# </OWL:Class>
graph.add((MyClassNode, RDF.type, OWL.Class))
graph.add((MyClassNode, RDFS.subClassOf, MyBaseClassNode))
graph.add((MyClassNode, RDFS.label, Literal("The type of class MyClass")))
graph.add((MyClassNode, RDFS.comment, Literal("The class of MyClass")))

# <OWL:DataTypeProperty rdf:ID="Name">
# <rdfs:domain rdf:resource="OWL:Thing"/>
# <rdfs:range rdf:resource="xsd:string"/>
# </OWL:DataTypeProperty>
MyDatatypePropertyNode = URIRef(LDT["MyDatProp"])
graph.add((MyDatatypePropertyNode, RDF.type, OWL.DatatypeProperty))
graph.add((MyDatatypePropertyNode, RDFS.domain, OWL.Thing))
graph.add((MyDatatypePropertyNode, RDFS.range, XSD.string))

#graph.add((MyClassNode, RDF.type, MyDatatypePropertyNode))




# Bind the OWL and LDT name spaces
graph.bind("owl", OWL)
graph.bind("ldt", LDT)

# https://www.w3.org/TR/owl-ref/#ClassDescription
#    Object properties link individuals to individuals.
#    Datatype properties link individuals to data values.

# print( graph.serialize(format='xml') )
print( graph.serialize(format='pretty-xml') )
