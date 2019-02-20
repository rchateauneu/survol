from rdflib.namespace import OWL, RDF, RDFS, XSD
import rdflib

import os
import sys


################################################################################

# "ref:CIM_LogicalElement"
# "ref:CIM_CollectionOfMSEs"
# "ref:__EventConsumer"
# "ref:CIM_Setting"
# "ref:CIM_LogicalElement"
# "ref:CIM_ManagedSystemElement"
# "object:__ACE"
# "object:__Namespace"
# "object:__Trustee"
# "object"
# "Object"
map_types_CIM_to_XSD = {
    "boolean": XSD.boolean,
    "Boolean": XSD.boolean,
    "string": XSD.string,
    "String": XSD.string,
    "uint8": XSD.integer,
    "uint16": XSD.integer,
    "sint32": XSD.integer,
    "uint32": XSD.integer,
    "Uint32": XSD.integer,
    "uint64": XSD.long,
    "Uint64": XSD.long,
    "datetime":XSD.dateTime,
    #"1":XSD.date,
    #"2":XSD.float,
    #"3":XSD.double,
    #"4":XSD.decimal,
    #"5":XSD.time,
    #"7":XSD.duration,
}

# owl_type: "xsd::string" etc... TODO: Transform this into XSD.string etc...
def PropNameToXsdType(prop_type):
    try:
        xsd_type = map_types_CIM_to_XSD[prop_type]
    except:
        INFO("PropNameToXsdType tp=%s",prop_type)
        xsd_type = XSD.string
    return xsd_type

################################################################################

# Construct the linked data tools namespace
# See lib_properties.py: primns = "http://primhillcomputers.com/survol"
LDT = rdflib.Namespace("http://www.primhillcomputers.com/survol#")

# Add the OWL class to the graph
# <OWL:Class rdf:ID="Service">
#     <rdfs:subClassOf rdf:resource="#System"/>
# </OWL:Class>
def AddClassToOwlDlOntology(graph, className, baseClassName, text_descr):

    # Create the node to add to the Graph
    MyClassNode = rdflib.URIRef(LDT[className])

    graph.add((MyClassNode, RDF.type, OWL.Class))
    if baseClassName:
        # Empty string if top-level class.
        MyBaseClassNode = rdflib.URIRef(LDT[baseClassName])
        graph.add((MyClassNode, RDFS.subClassOf, MyBaseClassNode))
    graph.add((MyClassNode, RDFS.label, rdflib.Literal(className)))
    if text_descr:
        graph.add((MyClassNode, RDFS.comment, rdflib.Literal(text_descr)))

# <OWL:DataTypeProperty rdf:ID="Name">
#     <rdfs:domain rdf:resource="OWL:Thing"/>
#     <rdfs:range rdf:resource="xsd:string"/>
# </OWL:DataTypeProperty>
def AddPropertyToOwlDlOntology(graph, propertyName, prop_type, prop_desc):
    MyDatatypePropertyNode = rdflib.URIRef(LDT[propertyName])
    graph.add((MyDatatypePropertyNode, RDF.type, OWL.DatatypeProperty))
    graph.add((MyDatatypePropertyNode, RDFS.domain, OWL.Thing))
    if prop_desc:
        graph.add((MyDatatypePropertyNode, RDFS.comment, rdflib.Literal(prop_desc)))
    if prop_type:
        xsd_type = PropNameToXsdType(prop_type)
        graph.add((MyDatatypePropertyNode, RDFS.range, xsd_type))


def CreateOwlDlOntology(map_classes, map_attributes):
    graph = rdflib.Graph()

    for class_name in map_classes:
        prop_dict = map_classes[class_name]
        base_class_name = prop_dict.get("base_class", "")
        text_descr = prop_dict.get("description", "")

        AddClassToOwlDlOntology(graph,class_name, base_class_name, text_descr)

    for prop_name in map_attributes:
        prop_dict = map_attributes[prop_name]
        prop_type = prop_dict.get("type", "")
        prop_desc = prop_dict.get("description", "")

        AddPropertyToOwlDlOntology(graph, prop_name, prop_type, prop_desc)

    # Bind the OWL and LDT name spaces
    graph.bind("owl", OWL)

    graph.bind("ldt", LDT)

    return graph

################################################################################

# Add the RDFS class to the graph
def AddClassToRdfsOntology(graph, className, baseClassName, text_descr):

    # Create the node to add to the Graph
    MyClassNode = rdflib.URIRef(LDT[className])

    graph.add((MyClassNode, RDF.type, RDFS.Class))
    if baseClassName:
        # Empty string if top-level class.
        MyBaseClassNode = rdflib.URIRef(LDT[baseClassName])
        graph.add((MyClassNode, RDFS.subClassOf, MyBaseClassNode))
    graph.add((MyClassNode, RDFS.label, rdflib.Literal(className)))
    if text_descr:
        graph.add((MyClassNode, RDFS.comment, rdflib.Literal(text_descr)))

def AddPropertyToRdfsOntology(graph, propertyName, prop_type, prop_desc):
    MyDatatypePropertyNode = rdflib.URIRef(LDT[propertyName])
    graph.add((MyDatatypePropertyNode, RDF.type, RDF.Property))
    if prop_desc:
        graph.add((MyDatatypePropertyNode, RDFS.comment, rdflib.Literal(prop_desc)))
    if prop_type:
        xsd_type = PropNameToXsdType(prop_type)
        graph.add((MyDatatypePropertyNode, RDFS.range, xsd_type))


def CreateRdfsOntology(map_classes, map_attributes):
    graph = rdflib.Graph()

    for class_name in map_classes:
        prop_dict = map_classes[class_name]
        base_class_name = prop_dict.get("base_class","")
        text_descr = prop_dict.get("description","")

        AddClassToRdfsOntology(graph,class_name, base_class_name, text_descr)

    for prop_name in map_attributes:
        prop_dict = map_attributes[prop_name]
        prop_type = prop_dict.get("type", "")
        prop_desc = prop_dict.get("description", "")

        AddPropertyToRdfsOntology(graph, prop_name, prop_type, prop_desc)

    # Bind the OWL and LDT name spaces
    graph.bind("owl", OWL)

    graph.bind("ldt", LDT)

    return graph

################################################################################

# This dumps the ontology to a HTTP socket.
# This can also save the results to a file, for later use.
def DumpOntology(graph, onto_filnam, out_dest):
    INFO("DumpOntology l=%s sys.argv=%s",len(sys.argv),str(sys.argv))

    def SaveToStream(the_stream):
        # It expects UTF8 with Python2 and Windows.
        # See lib_util.WrtAsUtf() which does the same.
        # TODO: Factorize code.
        # 'ascii' codec can't encode character u'\u2019' in position 604829: ordinal not in range(128)
        srlStr = graph.serialize(format='pretty-xml')
        try:
            # If it writes to a socket.
            the_stream.write( srlStr )
        except TypeError:
            the_stream.write( srlStr.decode('utf8') )

    try:
        os.environ["QUERY_STRING"]
        INFO("DumpOntology to stream")
        # lib_util.WrtAsUtf("Content-type: text/html\n\n")
        out_dest.write(u"Content-type: text/html\n\n")

        SaveToStream(out_dest)
    except KeyError:
        INFO("DumpOntology onto_filnam=%s",onto_filnam)
        outfil = open(onto_filnam,"w")
        SaveToStream(outfil)
        outfil.close()

################################################################################
