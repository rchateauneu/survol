# This encapsulates rdflib features, and may help to implement differently triplestore features.
from __future__ import print_function

import sys
import os
import re
import collections
import rdflib
import time
import datetime
import tempfile
from rdflib.namespace import RDF, RDFS, XSD
from rdflib import URIRef

# This will change soon after rdflib 5.0.0
# from rdflib.plugins.stores.memory import Memory
from rdflib.plugins.memory import IOMemory
import rdflib.plugins
import rdflib.plugins.stores
import rdflib.plugins.stores.concurrent


PredicateSeeAlso = RDFS.seeAlso
PredicateIsDefinedBy = RDFS.isDefinedBy
PredicateComment = RDFS.comment
PredicateType = RDF.type
#PredicateClass = RDFS.Class
PredicateLabel = RDFS.label
PredicateSubClassOf = RDFS.subClassOf


def IsLiteral(obj_rdf):
    return isinstance(obj_rdf, rdflib.term.Literal)


def IsURIRef(obj_rdf):
    return isinstance(obj_rdf, rdflib.term.URIRef)


def IsLink(obj):
    return isinstance(obj , (rdflib.URIRef, rdflib.BNode))


def unique_urls_dict(grph):
    """The returns the set of unique subjects or objects, instances and scripts, but no literals."""

    # A default dictionary of default dictionaries of lists.
    urls_dict = collections.defaultdict(lambda: collections.defaultdict(list))

    # Beware that the order might change each time.
    for k_sub, k_pred, k_obj in grph:
        pred_name = grph.qname(k_pred)
        urls_dict[k_sub][pred_name].append(str(k_obj))

        if not IsLiteral(k_obj):
            urls_dict[k_obj]
    return urls_dict


def get_urls_adjacency_list(grph, start_instance, filter_predicates):
    """It has to build an intermediary map because we have no simple way to find all edges
    starting from a node. Otherwise, we could use a classical algorithm (Dijkstra ?)"""
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

        if (str_start != "http://localhost") and (str_end != "http://localhost"):
            #INFO("urlStart=%s urlEnd=%s",urlStart,urlEnd)
            assert str_start.find("/localhost") < 0, "start local host"
            assert str_end.find("/localhost") < 0, "end local host"
            try:
                adjacency_list[url_start].add(url_end)
            except KeyError:
                adjacency_list[url_start] = set([url_end])

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


# TODO: Consider using SPARQL.
def triplestore_matching_strings(grph, search_string):
    """This returns a subset of a triplestore whose object matches a given string."""
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


def triplestore_to_stream_xml(grph, out_dest, a_format):
    """This writes a triplestore to a stream which can be a socket, file, a bytes or a str."""

    try:
        # This is tested with RDF and D3 for:
        # Windows
        #   CGI (cgiserver.py)
        #     '_io.FileIO': Py2 and Py3

        #   WSGI (wsgiserver.py)
        #     '_io.BytesIO': Py2 and Py3

        # Linux
        #   Apache
        #   CGI (cgiserver.py)
        #     'file': Py2 and Py3
        #   WSGI (wsgiserver.py)
        #     'str': Py2
        #     '_io.BytesIO': Py3

        #sys.stderr.write("type(out_dest)=%s\n" % type(out_dest))
        grph.serialize(destination=out_dest, format=a_format)
    except Exception as exc:
        ERROR("triplestore_to_stream_xml Exception:%s", exc)
        sys.stderr.write("ERROR:%s\n" % str(exc))
        raise


def triplestore_from_rdf_xml(doc_xml_rdf):
    """This reasonably assumes that the triplestore library is able to convert from RDF.
    This transforms a serialized XML document into RDF.
    See: https://rdflib.readthedocs.io/en/stable/apidocs/rdflib.html """

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
def _prop_name_to_xsd_type(prop_type):
    try:
        xsd_type = map_types_CIM_to_XSD[prop_type]
    except:
        INFO("_prop_name_to_xsd_type tp=%s",prop_type)
        xsd_type = XSD.string
    return xsd_type

################################################################################

# Construct the linked data tools namespace
# See lib_properties.py: primns = "http://primhillcomputers.com/survol"
# Beware that this URL is scattered at several places.
LDT = rdflib.Namespace("http://www.primhillcomputers.com/survol#")


def RdfsPropertyNode(property_name):
    return rdflib.URIRef(LDT[property_name])


def _rdfs_class_node(class_name):
    """Create the node to add to the Graph
    Example: "http://www.primhillcomputers.com/survol#CIM_DataFile" """
    return rdflib.URIRef(LDT[class_name])


def AddNodeToRdfsClass(grph, node_object, class_name, entity_label):
    """
    This adds to the RDF graph, some triples defining the class and label of an object.
    It is used when exporting an ontology.
    These triples are a RDF standard and can be used by other softwares.
    """
    node_class = _rdfs_class_node(class_name)
    grph.add((node_object, RDF.type, node_class))
    grph.add((node_object, RDFS.label, rdflib.Literal(entity_label)))


def CreateRdfsOntology(map_classes, map_attributes, graph=None):
    """
    This receives an ontology described in a neutral way,
    and adds to the graph the RDFS nodes describing it,
    or returns a new graph.

    This is used to translated Survol, WBEM or WMI ontology to RDF.
    """

    # Add the RDFS class to the graph
    def add_class_to_rdfs_ontology(the_graph, the_class_name, the_base_class_name, text_description):
        the_class_name = the_class_name.strip()
        if not the_class_name:
            raise Exception("Empty class name")

        node_class = _rdfs_class_node(the_class_name)

        the_graph.add((node_class, RDF.type, RDFS.Class))
        if the_base_class_name:
            # Empty string if top-level class.
            my_base_class_node = _rdfs_class_node(the_base_class_name)
            the_graph.add((node_class, RDFS.subClassOf, my_base_class_node))
        the_graph.add((node_class, RDFS.label, rdflib.Literal(the_class_name)))
        if text_description:
            the_graph.add((node_class, RDFS.comment, rdflib.Literal(text_description)))

    def add_property_to_rdfs_ontology(the_graph, property_name, property_type, property_domain,
                                      property_range, property_description):
        node_datatype_property = rdflib.URIRef(LDT[property_name])
        the_graph.add((node_datatype_property, RDF.type, RDF.Property))
        if property_description:
            the_graph.add((node_datatype_property, RDFS.comment, rdflib.Literal(property_description)))
        if property_type:
            xsd_type = _prop_name_to_xsd_type(property_type)
            the_graph.add((node_datatype_property, RDFS.range, xsd_type))
        if property_domain:
            node_domain_class = rdflib.URIRef(LDT[property_domain])
            the_graph.add((node_datatype_property, RDFS.domain, node_domain_class))
        if property_range:
            node_range_class = rdflib.URIRef(LDT[property_range])
            the_graph.add((node_datatype_property, RDFS.range, node_range_class))

    if not graph:
        graph = rdflib.Graph()

    for class_name in map_classes:
        prop_dict = map_classes[class_name]
        base_class_name = prop_dict.get("base_class", "")
        text_descr = prop_dict.get("class_description", "")

        add_class_to_rdfs_ontology(graph,class_name, base_class_name, text_descr)

    for prop_name in map_attributes:
        prop_dict = map_attributes[prop_name]
        prop_type = prop_dict.get("predicate_type", "")
        # This contains a list of class names.
        prop_domain = prop_dict.get("predicate_domain", [])
        prop_range = prop_dict.get("predicate_range", "")
        prop_desc = prop_dict.get("predicate_description", "")

        # The same key can exist for several classes.
        for one_class in prop_domain:
            add_property_to_rdfs_ontology(graph, prop_name, prop_type, one_class, prop_range, prop_desc)

    # Bind the LDT name spaces
    graph.bind("ldt", LDT)

    return graph

################################################################################


def CheckMinimalRdsfOntology(ontology_graph):
    """This is only for testing purpose.
    It checks that a minimal subset of classes and predicates are defined."""

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
        subject_node = _rdfs_class_node(subject_name) if subject_name else None
        predicate_node = _rdfs_class_node(predicate_name) if predicate_name else None
        object_node = _rdfs_class_node(object_name) if object_name else None

        triple_find = (subject_node, predicate_node, object_node)
        if not triple_find in ontology_graph:
            triple_name = (subject_name, predicate_name, object_name)
            ERROR("CheckMinimalRdsfOntology missing triple:%s %s %s", * triple_name )
            missing_triples.append(triple_name)
        return missing_triples


def check_rdf_ontology_conformance(rdf_graph):
    """
    All classes must be defined by RDF, for example:

    <rdf:Description rdf:about="http://www.primhillcomputers.com/survol#Name">
    <rdf:type rdf:resource="http://www.w3.org/1999/02/22-rdf-syntax-ns#Property"/>
    <rdfs:comment>Ontology predicate Name</rdfs:comment>
    <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#string"/>
    <rdfs:domain rdf:resource="http://www.primhillcomputers.com/survol#CIM_Directory"/>
    <rdfs:domain rdf:resource="http://www.primhillcomputers.com/survol#CIM_DataFile"/>
    </rdf:Description>

    <rdf:Description rdf:about="http://www.primhillcomputers.com/survol#options">
    <rdfs:comment>Predicate options</rdfs:comment>
    <rdfs:domain rdf:resource="http://www.primhillcomputers.com/survol#CIM_Directory"/>
    <rdf:type rdf:resource="http://www.w3.org/1999/02/22-rdf-syntax-ns#Property"/>
    <rdfs:range rdf:resource="http://www.w3.org/2001/XMLSchema#string"/>
    </rdf:Description>

    <rdf:Description rdf:about="http://www.primhillcomputers.com/survol#CIM_Directory">
    <rdfs:label>CIM_Directory</rdfs:label>
    <rdf:type rdf:resource="http://www.w3.org/2000/01/rdf-schema#Class"/>
    <rdfs:comment>Standard directory</rdfs:comment>
    </rdf:Description>
    """

    dict_domains = dict()
    dict_ranges = dict()
    dict_objects = dict()
    dict_labels = dict()
    dict_comments = dict()

    set_classes = set()
    set_properties = set()

    errors_list = []

    non_ontology_graph = rdflib.Graph()

    # First pass to build a dictionary of the content.
    for the_subject, the_predicate, the_object in rdf_graph:
        if the_predicate == RDF.type:
            if the_object == RDFS.Class:
                if the_subject in set_classes:
                    errors_list.append("Duplicated class %s" % the_subject)
                set_classes.add(the_subject)
            elif the_object == RDF.Property:
                if the_subject in set_properties:
                    errors_list.append("Duplicated property %s" % the_subject)
                set_properties.add(the_subject)
            else:
                if the_subject in dict_objects:
                    errors_list.append("Duplicated type %s => %s" % (the_subject, dict_objects[the_subject]))
                dict_objects[the_subject] = the_object
        elif the_predicate == RDFS.range:
            if the_subject in dict_ranges:
                errors_list.append("Duplicated range %s => %s" % (the_subject, dict_ranges[the_subject]))
            dict_ranges[the_subject] = the_object
        elif the_predicate == RDFS.domain:
            # Duplicate domains are allowed.
            #if the_subject in dict_domains:
            #    errors_list.append("Duplicated domain %s => %s" % (the_subject, dict_domains[the_subject]))
            dict_domains[the_subject] = the_object
        elif the_predicate == RDFS.label:
            if the_subject in dict_labels:
                errors_list.append("Duplicated label %s => %s" % (the_subject, dict_labels[the_subject]))
            dict_labels[the_subject] = the_object
        elif the_predicate == RDFS.comment:
            # Duplicate comments are allowed.
            #if the_subject in dict_comments:
            #    errors_list.append("Duplicated comment %s => %s" % (the_subject, dict_comments[the_subject]))
            dict_comments[the_subject] = the_object
        else:
            non_ontology_graph.add((the_subject, the_predicate, the_object))
            # print(str(the_subject), str(the_predicate), str(the_object))

    print("")
    print("Classes:", [str(a_class) for a_class in set_classes])
    print("Properties:", [str(a_prop) for a_prop in set_properties])
    # print("Objects:", [str(an_object) for an_object in dict_objects])

    for an_object, its_class in dict_objects.items():
        if its_class not in set_classes:
            errors_list.append("Missing class %s for object %s" % (its_class, an_object))

    # The remaining triples must use defined urls.
    for the_subject, the_predicate, the_object in non_ontology_graph:
        if the_predicate not in set_properties:
            errors_list.append("Missing property %s for object %s" % (the_predicate, the_subject))

    return errors_list


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

################################################################################


# The graph must be persistent and concurrently accessed.
# Several stores are possible (For example SqlLite), but SleepyCat is always installed with rdflib,
# so it is convenient to use it.
# https://code.alcidesfonseca.com/docs/rdflib/gettingstarted.html
_store_input = None
_events_conjunctive_graph = None


# Plugin stores
#
# Name                 Class
# Auditable            AuditableStore
# Concurrent           ConcurrentStore
# IOMemory             IOMemory
# SPARQLStore          SPARQLStore
# SPARQLUpdateStore    SPARQLUpdateStore
# Sleepycat            Sleepycat
# default              IOMemory

# https://github.com/RDFLib/rdflib-sqlalchemy
# SqlAlchemy Sample DBURI values::
# dburi = Literal("mysql://username:password@hostname:port/database-name?other-parameter")
# dburi = Literal("mysql+mysqldb://user:password@hostname:port/database?charset=utf8")
# dburi = Literal('postgresql+psycopg2://user:pasword@hostname:port/database')
# dburi = Literal('postgresql+pg8000://user:pasword@hostname:port/database')
# dburi = Literal('sqlite:////absolute/path/to/foo.db')
# dburi = Literal("sqlite:///%(here)s/development.sqlite" % {"here": os.getcwd()})
# dburi = Literal('sqlite://') # In-memory

# Modern versions of SQLite support an alternative system of connecting using a driver level URI,
# which has the advantage that additional driver-level arguments can be passed including options such as "read only".
# The Python sqlite3 driver supports this mode under modern Python 3 versions.
# The SQLAlchemy pysqlite driver supports this mode of use by specifing "uri=true" in the URL query string.
# The SQLite-level "URI" is kept as the "database" portion of the SQLAlchemy url (that is, following a slash):
#
# "sqlite:///file:path/to/database?mode=ro&uri=true"
# "sqlite:///file:path/to/database?check_same_thread=true&timeout=10&mode=ro&nolock=1&uri=true"
#


_events_storage_style = (None, )


def set_storage_style(*storage_style_tuple):
    """
    This says if the graph should be stored in memory or in SQLAlchemy or something else.
    Resets the connection even if the new storage style is identical.
    """
    global _events_storage_style
    global _store_input
    global _events_conjunctive_graph

    if _store_input is not None:
        del _store_input
        _store_input = None

    if _events_conjunctive_graph is not None:
        if _events_storage_style[0] == "SQLAlchemy":
            try:
                _events_conjunctive_graph.close()
            except Exception as exc:
                sys.stderr.write("set_storage_style Exception=%s\n" % exc)
        del _events_conjunctive_graph
        _events_conjunctive_graph = None

    _events_storage_style = storage_style_tuple

    _log_db_access("set_storage_style", "", "1", str(_events_storage_style))


def _check_globals(function_name):
    """Internal check."""
    if _store_input is None:
        raise Exception("%s _store_input should not be None" % function_name)
    if _events_conjunctive_graph is None:
        raise Exception("%s _events_conjunctive_graph should not be None" % function_name)


def _setup_global_graph():
    """Lazy creation of the graph used to store events by events generators, and read by CGI scripts. """
    global _store_input
    global _events_conjunctive_graph

    if _store_input is None:
        if _events_conjunctive_graph is not None:
            raise Exception("_events_conjunctive_graph should be None")

        if not isinstance(_events_storage_style, tuple):
            raise Exception("Wrong type for _events_storage_style")
        if _events_storage_style[0] == "IOMemory":
            _store_input = IOMemory()
            _events_conjunctive_graph = rdflib.ConjunctiveGraph(store=_store_input)
        elif _events_storage_style[0] == "SQLAlchemy":
            # How to install rdflib-sqlalchemy
            # pip install rdflib-sqlalchemy
            #
            # py -2.7 -m pip install rdflib-sqlalchemy
            #       from glob import glob
            #   ImportError: No module named glob
            #
            # py -3.6 -m pip install rdflib-sqlalchemy
            # OK

            sqlite_ident = rdflib.URIRef("rdflib_survol")
            # https://docs.sqlalchemy.org/en/13/dialects/sqlite.html#module-sqlalchemy.dialects.sqlite.pysqlite
            # _sqlite_uri = rdflib.Literal("sqlite://")
            # driver://user:pass@host/database
            # sqlite+pysqlite:///file_path
            # # absolute path on Windows
            # e = create_engine('sqlite:///C:\\path\\to\\database.db')
            # in-memory database
            # e = create_engine('sqlite://')
            # _sqlite_uri = rdflib.Literal("sqlite://")
            # engine=create_engine('sqlite:///:memory:')
            #sqlite_filename = r"C:\Users\rchateau\survol_events.sqlite"
            #_sqlite_uri = rdflib.Literal(r"sqlite:///%s" % sqlite_filename)

            sqlite_path = _events_storage_style[1]
            # This path might contain environment variables.
            sqlite_path_expanded = os.path.expandvars(sqlite_path)
            sqlite_uri = rdflib.Literal(sqlite_path_expanded)

            _store_input = rdflib.plugin.get("SQLAlchemy", rdflib.store.Store)(identifier=sqlite_ident)
            _events_conjunctive_graph = rdflib.ConjunctiveGraph(_store_input, identifier=sqlite_ident)
            try:
                # _events_conjunctive_graph.open(sqlite_uri, create=True)

                # Open previously created store, or create it if it doesn't exist yet
                _log_db_access("_setup_global_graph", "O", "1", sqlite_uri)
                rt = _events_conjunctive_graph.open(sqlite_uri, create=False)
            except Exception as exc:
                sys.stderr.write("sqlite_uri=%s. Exception=%s\n" % (sqlite_uri, exc))

                # According to the documentation, it should rather return this value instead of throwing.
                rt = rdflib.store.NO_STORE

            try:
                if rt == rdflib.store.NO_STORE:
                    # There is no underlying SQLAlchemy infrastructure, create it
                    _log_db_access("_setup_global_graph", "C", "2", sqlite_uri)
                    _events_conjunctive_graph.open(sqlite_uri, create=True)
                elif rt != rdflib.store.VALID_STORE:
                    raise Exception("sqlite_uri=%s rt=%d" % (sqlite_uri, rt))

            except Exception as exc:
                raise Exception("sqlite_uri=%s.Exception=%s" % (sqlite_uri, exc))

        else:
            raise Exception("Unknown storage style:" + str(_events_storage_style))

    _check_globals("_setup_global_graph")

    return _events_conjunctive_graph


def _url_to_context_node(the_url):
    """This returns a context for a graph from an url."""
    return URIRef(the_url)


def _log_db_access(function_name, access_type, step_name, url_name, data_size=-1):
    """For debugging. It writes in a file what happens to the db."""
    if access_type:
        # If not init.
        _check_globals(function_name)

    # This file shows all accesses to the events graph database.
    # TODO: This file should be truncated when the CGI server starts.
    # Also: This is purely for debugging.
    if "TRAVIS" in os.environ:
        log_db_file = None
    else:
        tmp_dir = tempfile.gettempdir()
        log_db_file = os.path.join(tmp_dir, "_survol_events_db.log")

    if not log_db_file:
        return

    timestamp_now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    open_try_count = 3
    for counter in range(open_try_count):
        try:
            db_log_file = open(log_db_file, "a")
            db_log_file.write("%s %6d %s f=%25s s=%s sz=%5d u=%s\n" % (
                timestamp_now,
                os.getpid(),
                access_type,
                function_name,
                step_name,
                data_size,
                url_name))
            db_log_file.flush()
            db_log_file.close()
            break
        except Exception as exc:
            sys.stderr.write("Did not work: %s. Retry\n" % exc)
            time.sleep(1)


_log_db_access("Init", "", "0", "")


def write_graph_to_events(the_url, input_graph):
    # TODO: It would be faster to store the events in this named graph.
    # TODO: Also, it is faster to directly store the triples.
    global _events_conjunctive_graph

    _setup_global_graph()
    _log_db_access("write_graph_to_events", "W", "1", the_url, len(input_graph))

    if the_url is None:
        _events_conjunctive_graph += input_graph
    else:
        url_node = _url_to_context_node(the_url)
        named_graph = rdflib.Graph(store=_store_input, identifier=url_node)
        named_graph += input_graph

    if _events_storage_style[0] == "SQLAlchemy":
        _events_conjunctive_graph.commit()

    len_input_graph = len(input_graph)

    _log_db_access("write_graph_to_events", "W", "2", the_url, len(input_graph))
    return len_input_graph


def read_events_to_graph(the_url, the_graph):
    """ This reads from the global graph, all triples in the context of the URL,
    which is the URL of a CGI script executed to create these events.
    Storing the events of the URL before reading them later, allows to decouple
    the generation of events and their usage, for example display etc... in another process."""

    _setup_global_graph()
    _log_db_access("read_events_to_graph", "R", "1", the_url)

    # Some rdflib examples here:
    # https://code.alcidesfonseca.com/docs/rdflib/assorted_examples.html
    url_node = _url_to_context_node(the_url)

    named_graph = _events_conjunctive_graph.get_context(url_node)

    the_graph += named_graph

    named_graph.remove((None, None, None))

    if _events_storage_style[0] == "SQLAlchemy":
        _events_conjunctive_graph.commit()

    _log_db_access("read_events_to_graph", "R", "2", the_url, len(the_graph))
    return len(the_graph)


def clear_all_events():
    global _events_conjunctive_graph
    sys.stderr.write("clear_all_events: Clearing events\n" )
    if _events_conjunctive_graph:
        sys.stderr.write("clear_all_events: %d events\n" % len(_events_conjunctive_graph))
        _events_conjunctive_graph.remove((None, None, None))
        if _events_storage_style[0] == "SQLAlchemy":
            _events_conjunctive_graph.commit()
        _events_conjunctive_graph = None
        sys.stderr.write("clear_all_events: Clearing events done\n")
    else:
        sys.stderr.write("clear_all_events: Nothing to clear\n")


def retrieve_all_events_to_graph_then_clear(output_graph):
    _setup_global_graph()
    _log_db_access("retrieve_all_events_to_graph_then_clear", "R", "1", "")

    output_graph += _events_conjunctive_graph
    _events_conjunctive_graph.remove((None, None, None))

    if _events_storage_style[0] == "SQLAlchemy":
        _events_conjunctive_graph.commit()

    _log_db_access("retrieve_all_events_to_graph_then_clear", "R", "2", "", len(output_graph))
    return len(output_graph)


def retrieve_events_to_graph(output_graph, entity_node):
    """Events about a single entity."""
    _setup_global_graph()
    _log_db_access("retrieve_events_to_graph", "R", "1", str(entity_node), len(output_graph))

    output_graph += _events_conjunctive_graph.triples((entity_node, None, None))
    _events_conjunctive_graph.remove((entity_node, None, None))

    if _events_storage_style[0] == "SQLAlchemy":
        _events_conjunctive_graph.commit()

    _log_db_access("retrieve_events_to_graph", "R", "2", str(entity_node), len(output_graph))
    return len(output_graph)


def events_count():
    _setup_global_graph()
    _log_db_access("events_count", "R", "1", "")

    len_graph = len(_events_conjunctive_graph)

    _log_db_access("events_count", "R", "2", "", len_graph)
    return len_graph


def time_stamp_now_node():
    # TODO: Use xsd:dateTimeStamp
    datetime_now = datetime.datetime.now()
    timestamp_literal = datetime_now.strftime("%Y-%m-%d %H:%M:%S")
    return rdflib.Literal(timestamp_literal)

