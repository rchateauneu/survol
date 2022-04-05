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

_key_classes = "classes"
_key_attributes = "attributes"
_key_rdf_graph = "rdf_graph"


def _get_ontology_component(ontology_name, ontology_extractor, component_name):
    """
    Most of times, there should be only one ontology in this cache: "wmi", "wbem" or "survol".
    This is because Survol will normally work with a single ontology, depending on the platform it is running on.

    :param ontology_name: wmi", "wbem", "survol". "survol" contains "wmi" or "wbem" ontology.
    :param ontology_extractor: Function to fetch the ontology if it is not in the cache.
    :param component_name: "classes", "attributes", "rdf_graph"
    :return: "CIM_ProcessExecutable.Antecedent" etc...
    """
    try:
        return _cache_ontologies[ontology_name][component_name]
    except KeyError:
        ontology_dict = _get_named_ontology_from_file(ontology_name, ontology_extractor, component_name)
        logging.info("Adding ontology %s to cache" % ontology_name)
        _cache_ontologies[ontology_name].update(ontology_dict)
        return ontology_dict[component_name]


def get_ontology_classes(ontology_name, ontology_extractor):
    """
    This returns the dict of classes of an ontology, stored in a cache.

    :param ontology_name: "WMI", "WBEM" etc...
    :param ontology_extractor:
    :return: A dict indexed by the class names.
    """
    return _get_ontology_component(ontology_name, ontology_extractor, _key_classes)


def _get_ontology_attributes(ontology_name, ontology_extractor):
    """
    This returns the dict of attributes of an ontology, stored in a cache.

    :param ontology_name: "WMI", "WBEM" etc...
    :param ontology_extractor:
    :return: A dict indexed by the predicate names.
    """
    return _get_ontology_component(ontology_name, ontology_extractor, _key_attributes)


def _get_ontology_rdf(ontology_name, ontology_extractor):
    """
    This returns the graph of an ontology, stored in a cache.

    :param ontology_name: "WMI", "WBEM" etc...
    :param ontology_extractor:
    :return: A RDFLIB graph.
    """
    return _get_ontology_component(ontology_name, ontology_extractor, _key_rdf_graph)


def serialize_ontology_to_graph(ontology_name, ontology_extractor, rdf_graph):
    """
    This fetches all triples of the given ontology and adds them to the graph.
    It is always done before returning a graph when executing a Sparql query,
    so all classes and properties are defined.
    """
    ontology_graph = _get_ontology_rdf(ontology_name, ontology_extractor)
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

    try:
        class_attributes = map_classes[entity_type]
    except KeyError:
        logging.warning("Class %s is not defined in this ontology" % entity_type)
        return

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
    attributes_map = _get_ontology_attributes(ontology_name, ontology_extractor)

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


def get_associated_class_role(ontology_name, ontology_extractor, attribute_name):
    attributes_map = _get_ontology_attributes(ontology_name, ontology_extractor)

    # TODO: This pass could be faster by storing a dictionary indexed by the associator name.

    the_associator_name, the_role = attribute_name.split(".")
    logging.debug("the_associator_name=%s the_role=%s", the_associator_name, the_role)
    attribute_properties = attributes_map[attribute_name]
    predicate_type = attribute_properties["predicate_type"]
    assert predicate_type.startswith("ref:")
    _, _, result_class = predicate_type.partition(":")
    return result_class, the_role


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

    There is a tricky and specific logic of returning only one key of the dict which defines an ontology,
    when the cache is already filled. This is needed for performance only because there are conceptually
    two levels of caching: In a dict, but also in files which are periodically refreshed (For example monthly)

    :param ontology_name:
    :param ontology_extractor:
    :param component_name: "classes", "attributes" or "rdf_graph"
    :return: A dict whose keys are "classes", "attributes" or "rdf_graph". Or the three if not in the cache
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
        if component_name == _key_classes:
            with open(path_classes) as fd_classes:
                map_classes = json.load(fd_classes)
                logging.info("loaded path_classes=%s", path_classes)
                return {_key_classes: map_classes}

        if component_name == _key_attributes:
            with open(path_attributes) as fd_attributes:
                map_attributes = json.load(fd_attributes)
                logging.info("loaded path_attributes=%s", path_attributes)
                return {_key_attributes: map_attributes}

        if component_name == _key_rdf_graph:
            with open(path_rdf_graph) as rdf_fd:
                ontology_graph = rdflib.Graph()
                ontology_graph.parse(rdf_fd, format='xml')
                logging.info("loaded path_rdf_graph=%s", path_rdf_graph)
                return {_key_rdf_graph: ontology_graph}

        raise Exception("Invalid component_name=%s" % component_name)
    except Exception as exc:
        logging.info("ManageOntologyCache %s: Caught: %s. Creating cache file.", ontology_name, exc)

    # The data are not in the cache, so it is fully recalculated, stored in three files and returned
    # to be stored in a local dict.
    # This typically happens once in a month and is very slow (several minutes) because of the number of classes.
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

    return {_key_classes: map_classes, _key_attributes: map_attributes, _key_rdf_graph: ontology_graph}


def _convert_ontology_to_rdf(map_classes, map_attributes, rdf_graph):
    """
    This creates a RDF graph containing the ontology described in Survol internal format
    made of two dicts, one for the class, the other for the attributes.
    This internal format works for WMI, WBEM and Survol ontology (which is much simpler).

    :param map_classes: A dict of classes names. Each class is itself defined with a dict.
    :param map_attributes: A dict of attributes. Each attribute is defined with a dict.
    :param rdf_graph: Where the ontology is added to.
    """

    # This first pass ensures that each class has a node.
    class_nodes = dict()
    for class_name, class_dict in map_classes.items():
        class_nodes[class_name] = lib_kbase.class_node_uriref(class_name)

    for class_name, class_dict in map_classes.items():
        class_node = class_nodes[class_name]
        if 'base_class' in class_dict:
            base_class_name = class_dict['base_class']
            # This must be defined because all nodes for each classes are defined in a previous loo.
            base_class_node = class_nodes[base_class_name]
            rdf_graph.add((class_node, rdflib.namespace.RDFS.subClassOf, base_class_node))

        rdf_graph.add((class_node, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
        rdf_graph.add((class_node, rdflib.namespace.RDFS.label, rdflib.Literal(class_name)))
        rdf_graph.add((class_node, rdflib.namespace.RDFS.comment, rdflib.Literal(class_dict["class_description"])))

    for property_name, property_dict in map_attributes.items():
        property_node = lib_kbase.property_node_uriref(property_name)
        rdf_graph.add((property_node, rdflib.namespace.RDFS.label, rdflib.Literal(property_name)))

        # Therer are no sub-properties in WMI.
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
        try:
            pred_dsc = property_dict["predicate_description"]
        except KeyError:
            pred_dsc = "Description not found for predicate " + predicate_type_class_name
        rdf_graph.add((property_node, rdflib.namespace.RDFS.comment, rdflib.Literal(pred_dsc)))
        # TODO: The description should be used.

