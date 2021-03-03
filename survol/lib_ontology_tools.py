import sys
import lib_util
import datetime
import json
import logging
import rdflib
import lib_util
import lib_kbase

# Internal ontologies are defined by two dicts and a RDF graph:
# - One for the classes,
# - another one for the attributes,
# - then the RDF graph.
# classes_map[class_name] = {"base_class": base_class_name, "class_description": text_descr}
# map_attributes[prop_obj.name] = { "predicate_type": prop_obj.type,"predicate_domain": class_name}
_cache_ontologies = {}


def get_named_ontology(ontology_name, ontology_extractor):
    """
    Returns the pair of dicts defining an ontology.
    """

    # Most of times, there should be only one ontology in this cache: "wmi", "wbem" or "survol".
    try:
        return _cache_ontologies[ontology_name]
    except KeyError:
        ontology_triple = _get_named_ontology_from_file(ontology_name, ontology_extractor)
        assert len(ontology_triple) == 3
        logging.info("Adding ontology %s to cache" % ontology_name)
        _cache_ontologies[ontology_name] = ontology_triple
        return ontology_triple


def serialize_ontology_to_graph(ontology_name, ontology_extractor, rdf_graph):
    """
    This fetches all triples of the given ontology and adds them to the graph.
    It is always done before returning a graph when executing a Sparql query,
    so all classes and properties are defined.
    """
    _, _, ontology_graph = get_named_ontology(ontology_name, ontology_extractor)
    # Copy all triples.
    # https://stackoverflow.com/questions/47058642/rdflib-add-triples-to-graph-in-bulk?rq=1
    rdf_graph += ontology_graph



################################################################################
def ManageLocalOntologyCache(ontology_name, ontology_extractor):
    """
    This caches data in files for performance.
    Extracting the entire ontology takes time.
    """
    tmp_dir = lib_util.get_temporary_directory()

    # A cache is valid for an entire month.
    # This cache is needed because WMI ontology extractors takes a lot of time.
    today_date = datetime.date.today()
    date_string = today_date.strftime("%Y%m")

    path_classes = "%s/ontology_classes.%s.%s.json" % (tmp_dir, ontology_name, date_string)
    path_attributes = "%s/ontology_attributes.%s.%s.json" % (tmp_dir, ontology_name, date_string)

    try:
        logging.info("ManageOntologyCache %s: Loading cached ontology from %s and %s",
             ontology_name, path_classes, path_attributes)
        fd_classes = open(path_classes)
        map_classes = json.load(fd_classes)
        fd_classes.close()

        fd_attributes = open(path_attributes)
        map_attributes = json.load(fd_attributes)
        fd_attributes.close()

        logging.info("ExtractWmiOntology %s: Loaded cached ontology from %s and %s",
             ontology_name, path_classes, path_attributes)
        return map_classes, map_attributes
    except Exception as exc:
        logging.info("ManageOntologyCache %s: Caught: %s. Creating cache file.", ontology_name, exc)

    map_classes, map_attributes = ontology_extractor()
    logging.info("ManageOntologyCache %s: Saving ontology to %s and %s",
        ontology_name, path_classes, path_attributes)

    fd_classes = open(path_classes, "w")
    json.dump(map_classes, fd_classes)
    fd_classes.close()

    fd_attributes = open(path_attributes, "w")
    json.dump(map_attributes, fd_attributes)
    fd_attributes.close()

    return map_classes, map_attributes

def _convert_ontology_to_rdf(map_classes, map_attributes, rdf_graph):

    # classes_map[class_name] = {"base_class": base_class_name, "class_description": text_descr}
    for class_name, class_dict in map_classes.items():
        class_node = rdflib.term.URIRef(lib_kbase.survol_url + class_name)
        rdf_graph.add((class_node, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
        rdf_graph.add((class_node, rdflib.namespace.RDFS.label, rdflib.Literal(class_name)))
        # TODO: The description "class_description" should be used.

    for property_name, property_dict in map_attributes.items():
        property_node = rdflib.term.URIRef(lib_kbase.survol_url + property_name)
        rdf_graph.add((property_node, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
        rdf_graph.add((property_node, rdflib.namespace.RDFS.label, rdflib.Literal(class_name)))

        rdf_graph.add((property_node, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
        attribute_domain = property_dict['predicate_domain']
        assert isinstance(attribute_domain, list)
        for domain_class_name in attribute_domain:
            #sys.stderr.write("domain_class_name=%s\n" % domain_class_name)
            #sys.stderr.write("domain_class_name=%s\n" % type(domain_class_name))
            #logging.debug("domain_class_name=%s" % domain_class_name)
            assert isinstance(domain_class_name, str)
            class_node = rdflib.term.URIRef(lib_kbase.survol_url + domain_class_name)
            rdf_graph.add((property_node, rdflib.namespace.RDFS.domain, class_node))
        predicate_type_name = property_dict['predicate_type']
        #sys.stderr.write("predicate_type_name=%s\n" % predicate_type_name)
        #sys.stderr.write("predicate_type_name=%s\n" % type(predicate_type_name))
        assert isinstance(predicate_type_name, str)

        # This maps WMI types to RDF types. This could be generated automatically,
        # because it is intentionaly a one-to-one mapping from string to type.
        # Only a small subset is used by Survol, the ones which are absolutely necessary from WMI.
        dict_rdf_str_to_type = {
            "string": rdflib.namespace.XSD.string,
            "integer": rdflib.namespace.XSD.integer,
            "boolean": rdflib.namespace.XSD.boolean,
            "double": rdflib.namespace.XSD.double,
            "dateTime": rdflib.namespace.XSD.dateTime,
        }
        # Could be: property_name="Antecedent" predicate_type_name="ref:Win32_ServerSession"
        if predicate_type_name.startswith("ref:"):
            predicate_type_class_name = predicate_type_name[4:]
            # Then it must be a class
            predicate_type = rdflib.term.URIRef(lib_kbase.survol_url + predicate_type_class_name)
        else:
            predicate_type = dict_rdf_str_to_type[predicate_type_name]
        rdf_graph.add((property_node, rdflib.namespace.RDFS.range, predicate_type))
        rdf_graph.add((property_node, rdflib.namespace.RDFS.label, rdflib.Literal(property_name)))
        # TODO: The description should be used.

