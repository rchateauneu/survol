import sys
import datetime
import json
import logging
import collections

import rdflib

import lib_util
import lib_kbase

# Internal ontologies are defined by two dicts and a RDF graph:
# - One for the classes,
# - another one for the attributes,
# - then the RDF graph.
#
# Examples:
# classes_map[class_name] = {"base_class": base_class_name, "class_description": text_descr}
# map_attributes[prop_obj.name] = { "predicate_type": prop_obj.type,"predicate_domain": class_name}

_cache_ontologies = collections.defaultdict(dict)


def _get_ontology_component(ontology_name, ontology_extractor, component_name):
    # Most of times, there should be only one ontology in this cache: "wmi", "wbem" or "survol".
    try:
        return _cache_ontologies[ontology_name][component_name]
    except KeyError:
        ontology_dict = _get_named_ontology_from_file(ontology_name, ontology_extractor, component_name)
        logging.info("Adding ontology %s to cache" % ontology_name)
        _cache_ontologies[ontology_name].update(ontology_dict)
        return ontology_dict[component_name]


def get_ontology_classes(ontology_name, ontology_extractor):
    return _get_ontology_component(ontology_name, ontology_extractor, "classes")


def get_ontology_attributes(ontology_name, ontology_extractor):
    return _get_ontology_component(ontology_name, ontology_extractor, "attributes")


def get_ontology_rdf(ontology_name, ontology_extractor):
    return _get_ontology_component(ontology_name, ontology_extractor, "rdf_graph")


def serialize_ontology_to_graph(ontology_name, ontology_extractor, rdf_graph):
    """
    This fetches all triples of the given ontology and adds them to the graph.
    It is always done before returning a graph when executing a Sparql query,
    so all classes and properties are defined.
    """
    ontology_graph = get_ontology_rdf(ontology_name, ontology_extractor)
    logging.debug("copy to graph")
    # Copy all triples.
    # https://stackoverflow.com/questions/47058642/rdflib-add-triples-to-graph-in-bulk?rq=1
    rdf_graph += ontology_graph


def class_associators(ontology_name, ontology_extractor, entity_type):
    """
    This returns the attributes names, that is, associator + result role,
    returning associated instances to this class.
    :param ontology_name: wmi", "wbem", "survol". "survol" inherits of "wmi" or "wbem" ontology.
    :param ontology_extractor: Function to fetch the ontology if it is not in the cache.
    :param entity_type: An instance class "CIM_DataFile" etc...
    :return: "CIM_ProcessExecutable.Antecedent" etc...
    """

    # CIM_ProcessExecutable.Antecedent:
    #     predicate_type:	"ref:CIM_DataFile"
    #     predicate_domain: ["CIM_Process"]
    # CIM_ProcessExecutable.Dependent:
    #     predicate_type:	"ref:CIM_Process"
    #     predicate_domain: ["CIM_DataFile"]
    logging.debug("entity_type=%s", entity_type)
    map_classes = get_ontology_classes(ontology_name, ontology_extractor)

    class_attributes = map_classes[entity_type]

    # Now select the non-keys attributes which are associators. Typically less than ten attributes.
    for attribute_name in class_attributes['non_key_properties_list']:
        if attribute_name.find(".") > 0:
            # Most of times, for a given accessor. it returns a single attribute,
            # except when the two roles have the same type,
            # which happens for example with the WMI associator Win32_SubDirectory.
            yield attribute_name


def get_associated_attribute(ontology_name, ontology_extractor, attribute_name):
    """
    Each associator has two roles which are represented as the concatenation of the associator and the role name,
    such as CIM_ProcessExecutable.Antecedent CIM_ProcessExecutable.Dependent which are called attribute names.
    This function receives an attribute name and returns properties the other leg of the associator,
    that is, the other role name and its class type.
    """
    attributes_map = get_ontology_attributes(ontology_name, ontology_extractor)

    # TODO: This pass could be faster by storing a dictionary indexed by the associator name.

    the_associator_name, the_role = attribute_name.split(".")
    logging.debug("the_associator_name=%s the_role=%s", the_associator_name, the_role)

    for one_attribute_name, one_attribute_properties in attributes_map.items():
        logging.debug("one_attribute_name=%s" % one_attribute_name)
        one_associator_name, associator_separator, one_role = one_attribute_name.partition(".")
        if associator_separator == "":
            # This attribute is not an associator followed by a role.
            continue
        if one_associator_name == the_associator_name and one_role != the_role:
            predicate_type = one_attribute_properties["predicate_type"]
            assert predicate_type.startswith("ref:")
            _, _, result_class = predicate_type.partition(":")
            return result_class, one_role
    raise Exception("No associated role for %s" % attribute_name)


def _get_named_ontology_from_file(ontology_name, ontology_extractor, component_name):
    """
    This caches an ontology in files for performance,
    because extracting the entire ontology takes time for example WMI ontology.
    Survol has an internal representation for ontologies based on Python dicts, which are better for fast access.
    This representation is generated by the function ontology_extractor.
    Because it does not come from RDF, but from Survol or WMI or WBEM,
    it does not need to be natively represented in RDF.
    However, this internal representation is converted to RDF to be returned in RDF graph.
    TODO: It should be stored at another place than the temporary directory, and possibly be encrypted.
    """
    tmp_dir = lib_util.get_temporary_directory()

    # A cache is valid for an entire month.
    # This cache is needed because WMI ontology extractors takes a lot of time.
    today_date = datetime.date.today()
    date_string = today_date.strftime("%Y%m")

    # These files contain the ontology are a valid for one month.
    path_classes = "%s/survol_ontology_classes.%s.%s.json" % (tmp_dir, ontology_name, date_string)
    path_attributes = "%s/survol_ontology_attributes.%s.%s.json" % (tmp_dir, ontology_name, date_string)
    path_rdf_graph = "%s/survol_ontology_rdf.%s.%s.xml" % (tmp_dir, ontology_name, date_string)

    try:
        logging.info("Loading ontology_name=%s from cache file", ontology_name)
        if component_name == "classes":
            with open(path_classes) as fd_classes:
                map_classes = json.load(fd_classes)
                logging.info("loaded path_classes=%s", path_classes)
                return {"classes": map_classes}

        if component_name == "attributes":
            with open(path_attributes) as fd_attributes:
                map_attributes = json.load(fd_attributes)
                logging.info("loaded path_attributes=%s", path_attributes)
                return {"attributes": map_attributes}

        if component_name == "rdf_graph":
            with open(path_rdf_graph) as rdf_fd:
                ontology_graph = rdflib.Graph()
                ontology_graph.parse(rdf_fd, format='xml')
                logging.info("loaded path_rdf_graph=%s", path_rdf_graph)
                return {"rdf_graph": ontology_graph}

        raise Exception("Invalid component_name=%s" % component_name)
    except Exception as exc:
        logging.info("ManageOntologyCache %s: Caught: %s. Creating cache file.", ontology_name, exc)

    map_classes, map_attributes = ontology_extractor()
    logging.info("ontology_name=%s saved to %s, %s, %s", ontology_name, path_classes, path_attributes, path_rdf_graph)

    with open(path_classes, "w") as fd_classes:
        json.dump(map_classes, fd_classes)

    with open(path_attributes, "w") as fd_attributes:
        json.dump(map_attributes, fd_attributes)

    # Also, regenerate the file containing the ontology in RDF format.
    ontology_graph = rdflib.Graph()
    _convert_ontology_to_rdf(map_classes, map_attributes, ontology_graph)
    logging.info("ManageOntologyCache %s: Saving RDF ontology to %s", ontology_name, path_rdf_graph)
    ontology_graph.serialize(destination=path_rdf_graph, format='xml')
    logging.info("ManageOntologyCache %s: Ontology caches recreated.", ontology_name)

    return {"classes": map_classes, "attributes": map_attributes, "rdf_graph": ontology_graph}


def _convert_ontology_to_rdf(map_classes, map_attributes, rdf_graph):
    """
    TODO: Near duplicate of CreateRdfsOntology

    This creates a RDF graph containing the ontology described in Survol internal format
    made of two dicts, one fpr the class, the other for the attributes.
    This internal format works for WMI, WBEM and Survol ontology (which is much simpler).
    """

    for class_name, class_dict in map_classes.items():
        class_node = lib_kbase.class_node_uriref(class_name)
        rdf_graph.add((class_node, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
        rdf_graph.add((class_node, rdflib.namespace.RDFS.label, rdflib.Literal(class_name)))
        # TODO: The description "class_description" should be used.

    for property_name, property_dict in map_attributes.items():
        property_node = lib_kbase.property_node_uriref(property_name)
        rdf_graph.add((property_node, rdflib.namespace.RDFS.label, rdflib.Literal(property_name)))

        rdf_graph.add((property_node, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
        attribute_domain = property_dict['predicate_domain']
        assert isinstance(attribute_domain, list)
        for domain_class_name in attribute_domain:
            assert isinstance(domain_class_name, str)
            class_node = lib_kbase.class_node_uriref(domain_class_name)
            rdf_graph.add((property_node, rdflib.namespace.RDFS.domain, class_node))
        predicate_type_name = property_dict['predicate_type']
        assert isinstance(predicate_type_name, str), "Should not be %s" % str(type(predicate_type_name))

        # This maps WMI-like types to RDF types. This could be generated automatically,
        # because it is intentionaly a one-to-one mapping from string to type.
        # Only a small subset is used by Survol, the ones which are absolutely necessary from WMI.
        dict_rdf_str_to_type = {
            "survol_string": rdflib.namespace.XSD.string,
            "survol_integer": rdflib.namespace.XSD.integer,
            "survol_boolean": rdflib.namespace.XSD.boolean,
            "survol_double": rdflib.namespace.XSD.double,
            "survol_dateTime": rdflib.namespace.XSD.dateTime,
        }
        # Could be: property_name="Antecedent" predicate_type_name="ref:Win32_ServerSession"
        if predicate_type_name.startswith("ref:"):
            predicate_type_class_name = predicate_type_name[4:]
            # Then it can only be a class
            predicate_type = lib_kbase.class_node_uriref(predicate_type_class_name)
        else:
            try:
                predicate_type = dict_rdf_str_to_type[predicate_type_name]
            except KeyError as exc:
                logging.error("Cannot map literal type:%s" % predicate_type_name)
                raise
        rdf_graph.add((property_node, rdflib.namespace.RDFS.range, predicate_type))
        rdf_graph.add((property_node, rdflib.namespace.RDFS.label, rdflib.Literal(property_name)))
        # TODO: The description should be used.

