# Encapsulate rdflib features.
# This is just in case another triplestore implementation would be more convenient.

import sys
sys.stderr.write("BEFORE import\n")
sys.stderr.write("sys.path=%s\n"%str(sys.path))

import rdflib
# Several combinaisons for Travis.
from rdflib.namespace import RDF, RDFS, XSD

import sys
import re

PredicateSeeAlso = RDFS.seeAlso
PredicateIsDefinedBy = RDFS.isDefinedBy
PredicateComment = RDFS.comment
PredicateType = RDF.type
PredicateClass = RDFS.Class

def IsLiteral(objRdf):
    return isinstance(objRdf, (rdflib.term.Literal))

def IsURIRef(objRdf):
    return isinstance(objRdf, (rdflib.term.URIRef))

def IsLink(obj):
    return isinstance( obj , (rdflib.URIRef, rdflib.BNode))

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
def enumerate_urls(grph):
    urlsSet = set()

    # Beware that the order might change each time.
    for kSub,kPred,kObj in grph:
        urlsSet.add(kSub)

        if not IsLiteral(kObj):
            urlsSet.add(kObj)
    return urlsSet

# It has to build an intermediary map because we have no simple way to find all edges
# starting from a node. Otherwise, we could use a classical algorithm (Dijkstra ?)
def get_urls_adjacency_list(grph,startInstance,filterPredicates):
    DEBUG("startInstance=%s type=%s",str(startInstance),str(type(startInstance)))
    # Each node maps to the list of the nodes it is directly connected to.
    adjacency_list = dict()

    # This takes an edge and updates the map.
    def InsertEdge(urlStart,urlEnd):
        #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
        # This keeps only Survol instances urls.
        strStart = str(urlStart)
        strEnd = str(urlEnd)
        # TODO: Make this test better.

        #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)

        if (strStart != "http://localhost") and (strEnd != "http://localhost"):
            #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            assert strStart.find("/localhost") < 0, "start local host"
            assert strEnd.find("/localhost") < 0, "end local host"
            #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            try:
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
                adjacency_list[urlStart].add(urlEnd)
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            except KeyError:
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
                adjacency_list[urlStart] = set([urlEnd])
                #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
        #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)

    DEBUG("len(grph)=%d",len(grph))

    # Connected in both directions.
    for kSub,kPred,kObj in grph:
        # TODO: Like in Grph2Json(), we could filter when kPred = pc.property_script = MakeProp("script")
        # TODO: because this can only be a script.
        if kPred in filterPredicates:
            continue

        if (not IsLiteral(kSub)) and (not IsLiteral(kObj)):

            #if str(kSub).find("entity.py") < 0:
            #    raise Exception("Broken1 %s %s %s"%(kSub,kPred,kObj))
            #if str(kObj).find("entity.py") < 0:
            #    raise Exception("Broken2 %s %s %s"%(kSub,kPred,kObj))

            InsertEdge(kSub,kObj)
            InsertEdge(kObj,kSub)
    #DEBUG("str(adjacency_list)=%s",str(adjacency_list))

    return adjacency_list


# This returns a subset of a triplestore whose object matches a given string.
# TODO: Consider using SparQL.
def triplestore_matching_strings(grph,searchString):
    DEBUG("triplestore_matching_strings: searchString=%s"%searchString)
    # Beware that the order might change each time.
    compiledRgx = re.compile(searchString)
    for kSub,kPred,kObj in grph:
        if IsLiteral(kObj):
            # Conversion to string in case it would be a number.
            strObj = str(kObj.value)
            if compiledRgx.match(strObj):
                #DEBUG("strObj=%s YES"%strObj)
                # yield strObj
                yield (kSub,kPred,kObj)
            #else:
            #    DEBUG("strObj=%s NO"%strObj)

def triplestore_all_strings(grph):
    DEBUG("triplestore_all_strings")
    # Beware that the order might change each time.
    for kSub,kPred,kObj in grph:
        if IsLiteral(kObj):
            # Conversion to string in case it would be a number.
            strObj = str(kObj.value)
            yield (kSub,kPred,kObj)

# This writes a triplestore to a stream which can be a socket or a file.
def triplestore_to_stream_xml(grph,out_dest, a_format):

    # a_format='pretty-xml', 'xml'

    # With Py2 and StringIO or BytesIO, it raises "TypeError: unicode argument expected, got 'str'"
    # grph.serialize( destination = out_dest, format="xml")
    # There might be a way to serialize directory to the socket.
    try:
        strXml = grph.serialize( destination = None, format=a_format)
    except Exception as ex:
        ERROR("triplestore_to_stream_xml Exception:%s",ex)
        raise
    if sys.version_info >= (3,):
        # Really horrible piece of code, because out_dest might expect a str or a bytes,
        # depending on its type.
        try:
            #out_dest.write(strXml.decode('latin1'))
            # TypeError: string argument expected, got 'bytes'
            out_dest.write(strXml)
        except TypeError as exc:
            DEBUG("triple_store_to_stream_xml. tp=%s exc=%s.",str(type(strXml)),str(exc))
            try:
                # TypeError: a bytes-like object is required, not 'str'
                out_dest.write(strXml.decode('latin1'))
            except TypeError as exc:
                ERROR("triple_store_to_stream_xml. tp=%s exc=%s. Cannot write:%s", str(type(strXml)), str(exc), strXml)
                raise
    else:
        # out_dest.write(strXml.decode('latin1'))
        try:
            out_dest.write(strXml)
        except:
            out_dest.write(strXml.decode('utf8'))


# This reasonably assumes that the triplestore library is able to convert from RDF.
# This transforms a serialize XML document into RDF.
# See: https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html
def triplestore_from_rdf_xml(docXmlRdf):
    # This is the inverse operation of: grph.serialize( destination = out_dest, format="xml")
    grph = rdflib.Graph()
    grph.parse(data=docXmlRdf, format="application/rdf+xml")
    return grph

# See https://rdflib.readthedocs.io/en/stable/merging.html for how it uses rdflib.
def triplestore_add(tripleStoreA,tripleStoreB):
    grphResult = tripleStoreA + tripleStoreB
    return grphResult

# See https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html which does qll the work.
def triplestore_sub(tripleStoreA,tripleStoreB):
    grphResult = tripleStoreA - tripleStoreB
    return grphResult


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

# Create the node to add to the Graph
def RdfsClassNode(className):
    return rdflib.URIRef(LDT[className])

def AddNodeToRdfsClass(grph, nodeObject, className, entity_label):
    nodeClass = RdfsClassNode(className)
    grph.add((nodeObject, RDF.type, nodeClass))
    grph.add((nodeObject, RDFS.label, rdflib.Literal(entity_label)))

# This receives an ontology described in a neutral way,
# and adds to the graph the RDFS nodes describing it.
def CreateRdfsOntology(map_classes, map_attributes, graph=None):
    # TODO: Create a cache, because WMI is very slow.


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
        prop_domain = prop_dict.get("predicate_domain", "")
        prop_range = prop_dict.get("predicate_range", "")
        prop_desc = prop_dict.get("predicate_description", "")

        AddPropertyToRdfsOntology(graph, prop_name, prop_type, prop_domain, prop_range, prop_desc)

    # Bind the LDT name spaces
    graph.bind("ldt", LDT)

    return graph

################################################################################

# TODO: We could use the original RDFS predicate instead of replacing.
def triplestore_set_comment(grph, predicate_for_comment):
    # predicate_RDFS_comment = RDFS.comment
    for kSub,kPred,kObj in grph.triples((None, predicate_for_comment, None)):
        grph.add((kSub, RDFS.comment, kObj))
        grph.remove((kSub, kPred, kObj))
        pass
################################################################################


# The QName is an abbreviation of URI reference with the namespace function for XML, for an edge.
# Transforms "http://primhillcomputers.com/ontologies/ppid" into "ppid"
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
    # Nothing really interesting at the moment, just hardcodes.
    #return lib_properties.prop_color(prop)

