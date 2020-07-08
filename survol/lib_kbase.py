# This encapsulates rdflib features, and may help to implement differently triplestore features.

import sys
import re
import collections
import rdflib
from rdflib.namespace import RDF, RDFS, XSD

PredicateSeeAlso = RDFS.seeAlso
PredicateIsDefinedBy = RDFS.isDefinedBy
PredicateComment = RDFS.comment
PredicateType = RDF.type
PredicateClass = RDFS.Class
PredicateLabel = RDFS.label
PredicateSubClassOf = RDFS.subClassOf


def IsLiteral(obj_rdf):
    return isinstance(obj_rdf, rdflib.term.Literal)


def IsURIRef(obj_rdf):
    return isinstance(obj_rdf, rdflib.term.URIRef)


def IsLink(obj):
    return isinstance(obj , (rdflib.URIRef, rdflib.BNode))


def MakeNodeLiteral(value):
    return rdflib.Literal(value)


# This returns an object which, whose string conversion is identical to the input string.
# Beware that it is sometimes called recursively.
def MakeNodeUrl(url):
    uriRef = rdflib.term.URIRef(url)
    # sys.stderr.write("MakeNodeUrl url=%s uriRef=%s\n"%(url,uriRef))
    return uriRef


def MakeNamespace(primns):
    pc = rdflib.Namespace(primns)
    return pc


def MakeGraph():
    return rdflib.Graph()


# The returns the set of unique subjects or objects,
# instances and scripts, but no literals.
def unique_urls_dict(grph):
    # A default dictionary of default dictionaries of lists.
    urls_dict = collections.defaultdict(lambda: collections.defaultdict(list))

    # Beware that the order might change each time.
    for k_sub, k_pred, k_obj in grph:
        pred_name = grph.qname(k_pred)
        urls_dict[k_sub][pred_name].append(str(k_obj))

        if not IsLiteral(k_obj):
            urls_dict[k_obj]
    return urls_dict


# It has to build an intermediary map because we have no simple way to find all edges
# starting from a node. Otherwise, we could use a classical algorithm (Dijkstra ?)
def get_urls_adjacency_list(grph, start_instance, filter_predicates):
    DEBUG("startInstance=%s type=%s", str(start_instance), str(type(start_instance)))
    # Each node maps to the list of the nodes it is directly connected to.
    adjacency_list = dict()

    # This takes an edge and updates the map.
    def _insert_edge(url_start, url_end):
        #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
        # This keeps only Survol instances urls.
        str_start = str(url_start)
        str_end = str(url_end)
        # TODO: Make this test better.

        #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)

        if (str_start != "http://localhost") and (str_end != "http://localhost"):
            #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            assert str_start.find("/localhost") < 0, "start local host"
            assert str_end.find("/localhost") < 0, "end local host"
            #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            try:
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
                adjacency_list[url_start].add(url_end)
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            except KeyError:
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
                adjacency_list[url_start] = set([url_end])
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
        #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)

    DEBUG("len(grph)=%d",len(grph))

    # Connected in both directions.
    for k_sub, k_pred, k_obj in grph:
        # TODO: Like in Grph2Json(), we could filter when k_pred = pc.property_script = MakeProp("script")
        # TODO: because this can only be a script.
        if k_pred in filter_predicates:
            continue

        if (not IsLiteral(k_sub)) and (not IsLiteral(k_obj)):
            _insert_edge(k_sub, k_obj)
            _insert_edge(k_obj, k_sub)
    #DEBUG("str(adjacency_list)=%s",str(adjacency_list))

    return adjacency_list


# This returns a subset of a triplestore whose object matches a given string.
# TODO: Consider using SparQL.
def triplestore_matching_strings(grph, search_string):
    DEBUG("triplestore_matching_strings: search_string=%s" % search_string)
    # Beware that the order might change each time.
    compiled_rgx = re.compile(search_string)
    for k_sub, k_pred, k_obj in grph:
        if IsLiteral(k_obj):
            # Conversion to string in case it would be a number.
            str_obj = str(k_obj.value)
            if compiled_rgx.match(str_obj):
                yield k_sub, k_pred, k_obj


def triplestore_all_strings(grph):
    DEBUG("triplestore_all_strings")
    # Beware that the order might change each time.
    for k_sub, k_pred, k_obj in grph:
        if IsLiteral(k_obj):
            # Conversion to string in case it would be a number.
            yield k_sub, k_pred, k_obj


# This writes a triplestore to a stream which can be a socket or a file.
def triplestore_to_stream_xml(grph, out_dest, a_format):

    # a_format='pretty-xml', 'xml'

    # With Py2 and StringIO or BytesIO, it raises "TypeError: unicode argument expected, got 'str'"
    # grph.serialize( destination = out_dest, format="xml")
    # There might be a way to serialize directory to the socket.
    try:
        str_xml = grph.serialize(destination = None, format=a_format)
    except Exception as exc:
        ERROR("triplestore_to_stream_xml Exception:%s", exc)
        raise
    if sys.version_info >= (3,):
        # Really horrible piece of code, because out_dest might expect a str or a bytes,
        # depending on its type.
        try:
            out_dest.write(str_xml)
        except TypeError as exc:
            DEBUG("triple_store_to_stream_xml. tp=%s exc=%s.", str(type(str_xml)), str(exc))
            try:
                # TypeError: a bytes-like object is required, not 'str'
                out_dest.write(str_xml.decode('latin1'))
            except TypeError as exc:
                ERROR("triple_store_to_stream_xml. tp=%s exc=%s. Cannot write:%s", str(type(str_xml)), str(exc), str_xml)
                raise
    else:
        try:
            out_dest.write(str_xml)
        except:
            out_dest.write(str_xml.decode('utf8'))


# This reasonably assumes that the triplestore library is able to convert from RDF.
# This transforms a serialize XML document into RDF.
# See: https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html
def triplestore_from_rdf_xml(doc_xml_rdf):
    # This is the inverse operation of: grph.serialize( destination = out_dest, format="xml")
    grph = rdflib.Graph()
    try:
        grph.parse(data=doc_xml_rdf, format="application/rdf+xml")
    except Exception as exc:
        # This is the exception message we want to split: "<unknown>:8:50: not well-formed (invalid token)"
        # Attempt to display exactly the error if it is like "<unknown>:8:50: not well-formed (invalid token)"
        exception_as_string = str(exc)
        exception_split = exception_as_string.split(":")
        if len(exception_split) >= 4 and exception_split[0] == "<unknown>":
            line_index = int(exception_split[1])
            column_index = int(exception_split[2])
            document_by_lines = doc_xml_rdf.split("\n")
            faulty_line = document_by_lines[line_index]
            ERROR("triplestore_from_rdf_xml index=%d faulty_line=%s", column_index, faulty_line)
        else:
            ERROR("triplestore_from_rdf_xml exc=%s docXmlRdf...=%s", exc, doc_xml_rdf[:20])
        raise
    return grph


# See https://rdflib.readthedocs.io/en/stable/merging.html for how it uses rdflib.
def triplestore_add(triple_store_a, triple_store_b):
    grph_result = triple_store_a + triple_store_b
    return grph_result


# See https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html which does qll the work.
def triplestore_sub(triple_store_a, triple_store_b):
    grph_result = triple_store_a - triple_store_b
    return grph_result


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
# Beware that this URL is scattered at several places.
LDT = rdflib.Namespace("http://www.primhillcomputers.com/survol#")


def RdfsPropertyNode(property_name):
    return rdflib.URIRef(LDT[property_name])


# Create the node to add to the Graph
# Example: "http://www.primhillcomputers.com/survol#CIM_DataFile"
def RdfsClassNode(class_name):
    return rdflib.URIRef(LDT[class_name])


def AddNodeToRdfsClass(grph, nodeObject, className, entity_label):
    nodeClass = RdfsClassNode(className)
    grph.add((nodeObject, RDF.type, nodeClass))
    grph.add((nodeObject, RDFS.label, rdflib.Literal(entity_label)))


# This receives an ontology described in a neutral way,
# and adds to the graph the RDFS nodes describing it.
def CreateRdfsOntology(map_classes, map_attributes, graph=None):
    # Add the RDFS class to the graph
    def AddClassToRdfsOntology(graph, className, baseClassName, text_descr):
        className = className.strip()
        if not className:
            raise Exception("Empty class name")

        nodeClass = RdfsClassNode(className)

        graph.add((nodeClass, RDF.type, RDFS.Class))
        if baseClassName:
            # Empty string if top-level class.
            MyBaseClassNode = RdfsClassNode(baseClassName)
            graph.add((nodeClass, RDFS.subClassOf, MyBaseClassNode))
        graph.add((nodeClass, RDFS.label, rdflib.Literal(className)))
        if text_descr:
            graph.add((nodeClass, RDFS.comment, rdflib.Literal(text_descr)))

    def AddPropertyToRdfsOntology(graph, prop_name, prop_type, prop_domain, prop_range, prop_desc):
        nodeDatatypeProperty = rdflib.URIRef(LDT[prop_name])
        graph.add((nodeDatatypeProperty, RDF.type, RDF.Property))
        if prop_desc:
            graph.add((nodeDatatypeProperty, RDFS.comment, rdflib.Literal(prop_desc)))
        if prop_type:
            xsd_type = PropNameToXsdType(prop_type)
            graph.add((nodeDatatypeProperty, RDFS.range, xsd_type))
        if prop_domain:
            nodeDomainClass = rdflib.URIRef(LDT[prop_domain])
            graph.add((nodeDatatypeProperty, RDFS.domain, nodeDomainClass))
        if prop_range:
            nodeRangeClass = rdflib.URIRef(LDT[prop_range])
            graph.add((nodeDatatypeProperty, RDFS.range, nodeRangeClass))

    if not graph:
        graph = rdflib.Graph()

    for class_name in map_classes:
        prop_dict = map_classes[class_name]
        base_class_name = prop_dict.get("base_class","")
        text_descr = prop_dict.get("class_description","")

        AddClassToRdfsOntology(graph,class_name, base_class_name, text_descr)

    for prop_name in map_attributes:
        prop_dict = map_attributes[prop_name]
        prop_type = prop_dict.get("predicate_type", "")
        # This contains a list of class names.
        prop_domain = prop_dict.get("predicate_domain", [])
        prop_range = prop_dict.get("predicate_range", "")
        prop_desc = prop_dict.get("predicate_description", "")

        # The same key can exist for several classes.
        for one_class in prop_domain:
            AddPropertyToRdfsOntology(graph, prop_name, prop_type, one_class, prop_range, prop_desc)

    # Bind the LDT name spaces
    graph.bind("ldt", LDT)

    return graph

################################################################################


# This is only for testing purpose.
# It checks that a minimal subset of classes and predicates are defined.
def CheckMinimalRdsfOntology(ontology_graph):
    # print("ontology_graph=",ontology_graph)

    # Quick logging for debugging.
    cnt = 0
    for ontology_subject, ontology_predicate, ontology_object in ontology_graph:
        # "http://www.primhillcomputers.com/survol#CIM_DataFile"
        print("ontology_subject=", ontology_subject)
        print("ontology_predicate=", ontology_predicate)
        print("ontology_object=", ontology_object)
        cnt += 1
        if cnt == 3:
            break

    """
    *** Survol:
    ontology_subject= http://www.primhillcomputers.com/survol#CIM_Process
    ontology_predicate= http://www.w3.org/2000/01/rdf-schema#label
    ontology_object= CIM_Process        

    ontology_subject= http://www.primhillcomputers.com/survol#CIM_Process
    ontology_predicate= http://www.w3.org/1999/02/22-rdf-syntax-ns#type
    ontology_object= http://www.w3.org/2000/01/rdf-schema#Class

    ontology_subject= http://www.primhillcomputers.com/survol#Handle
    ontology_predicate= http://www.w3.org/2000/01/rdf-schema#domain
    ontology_object= http://www.primhillcomputers.com/survol#CIM_Process

    ontology_subject= http://www.primhillcomputers.com/survol#Handle
    ontology_predicate= http://www.w3.org/1999/02/22-rdf-syntax-ns#type
    ontology_object= http://www.w3.org/1999/02/22-rdf-syntax-ns#Property

    ontology_subject= http://www.primhillcomputers.com/survol#Name
    ontology_predicate= http://www.w3.org/2000/01/rdf-schema#domain
    ontology_object= http://www.primhillcomputers.com/survol#CIM_DataFile

    ontology_subject= http://www.primhillcomputers.com/survol#Name
    ontology_predicate= http://www.w3.org/1999/02/22-rdf-syntax-ns#type
    ontology_object= http://www.w3.org/1999/02/22-rdf-syntax-ns#Property

    ontology_subject= http://www.primhillcomputers.com/survol#CIM_Directory
    ontology_predicate= http://www.w3.org/1999/02/22-rdf-syntax-ns#type
    ontology_object= http://www.w3.org/2000/01/rdf-schema#Class

    *** WMI:
    ontology_subject= http://www.primhillcomputers.com/survol#CIM_Process
    ontology_predicate= http://www.w3.org/2000/01/rdf-schema#label
    ontology_object= CIM_Process

    ontology_subject= http://www.primhillcomputers.com/survol#CIM_DataFile
    ontology_predicate= http://www.w3.org/1999/02/22-rdf-syntax-ns#type
    ontology_object= http://www.w3.org/2000/01/rdf-schema#Class

    ontology_subject= http://www.primhillcomputers.com/survol#CIM_DataFile
    ontology_predicate= http://www.w3.org/2000/01/rdf-schema#label
    ontology_object= CIM_DataFile

    ontology_subject= http://www.primhillcomputers.com/survol#CIM_Directory
    ontology_predicate= http://www.w3.org/2000/01/rdf-schema#label
    ontology_object= CIM_Directory

    # We do not have CIM_Process and CIM_Directory #Class node ?
    # Where are the predicates ?
    """

    # Some classes must be shared by all ontologies: This allows to merge triples
    # extracted by WMI, WBEM or Survol providers.
    shared_classes = [
        ("CIM_Process", None, None),
        ("CIM_DataFile", None, None),
        ("CIM_Directory", None, None),
        ("CIM_Process", RDF.type, RDFS.Class),
        ("CIM_DataFile", RDF.type, RDFS.Class),
        ("CIM_Directory", RDF.type, RDFS.Class),
    ]

    missing_triples = []
    for subject_name, predicate_name, object_name in shared_classes:
        subject_node = RdfsClassNode(subject_name) if subject_name else None
        predicate_node = RdfsClassNode(predicate_name) if predicate_name else None
        object_node = RdfsClassNode(object_name) if object_name else None

        triple_find = (subject_node, predicate_node, object_node)
        if not triple_find in ontology_graph:
            triple_name = (subject_name, predicate_name, object_name)
            ERROR("CheckMinimalRdsfOntology missing triple:%s %s %s", * triple_name )
            missing_triples.append(triple_name)
        return missing_triples

################################################################################


# TODO: We could use the original RDFS predicate instead of replacing.
def triplestore_set_comment(grph, predicate_for_comment):
    # predicate_RDFS_comment = RDFS.comment
    for k_sub, k_pred, k_obj in grph.triples((None, predicate_for_comment, None)):
        grph.add((k_sub, RDFS.comment, k_obj))
        grph.remove((k_sub, k_pred, k_obj))

################################################################################


# The QName is an abbreviation of URI reference with the namespace function for XML, for an edge.
# Transforms "http://primhillcomputers.com/ontologies/ppid" into "ppid"
# See lib_sparql_custom_evals.survol_url = "http://www.primhillcomputers.com/survol#"
# A CGI parameter might be there (CGIPROP)
# See lib_properties.PropToQName
def qname(x, grph):
    try:
        q = grph.compute_qname(x)
        # q[0] is the shortened namespace "ns"
        # Could return q[0] + ":" + q[2]
        return q[2]
    except:
        return x

