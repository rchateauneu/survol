"""Stores and retrieves data related to an entity."""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020-2021, Primhill Computers"
__license__     = "GPL"

import sys
import six
import rdflib

import lib_uris
import lib_common
import lib_util
import lib_kbase


def json_moniker_to_node(entity_type, entity_attributes_dict):
    assert isinstance(entity_type, (six.binary_type, six.text_type))
    assert isinstance(entity_attributes_dict, dict)

    ontology_list = lib_util.OntologyClassKeys(entity_type)

    # TODO: Only the properties we need. In fact, they should come in the right order.
    # TODO: Make this faster by assuming this is a list of key-value pairs.
    entity_ids_dict = {ontology_attribute_name: entity_attributes_dict[ontology_attribute_name]
                       for ontology_attribute_name in ontology_list}

    rdf_url = lib_uris.gUriGen.node_from_dict(entity_type, entity_ids_dict)
    return rdf_url


def json_triple_to_rdf_triple(subject_value_json, predicate_value_json, object_value_json):
    """Transforms a triple in JSON representation, into the rdflib triple.
    This JSON representation is also used for testing.
    """

    assert isinstance(subject_value_json, tuple) and len(subject_value_json) == 2
    subject_node = json_moniker_to_node(*subject_value_json)

    # The object might be another CIM object or a literal.
    # We should check the form: ("string", {})
    if isinstance(object_value_json, tuple) and len(object_value_json) == 2:
        object_node = json_moniker_to_node(*object_value_json)
    else:
        object_node = rdflib.Literal(object_value_json)

    url_predicate = lib_common.MakeProp(predicate_value_json)
    rdf_triple = (subject_node, url_predicate, object_node)
    return rdf_triple


def store_events_as_json_triples_list(json_data_list):
    """Triples stored in JSON format are used when creating triples in dockit.
    They are also used for testing."""
    rdflib_graph = _json_triples_to_graph(json_data_list)
    return lib_kbase.write_graph_to_events(None, rdflib_graph)


def _json_triples_to_graph(json_triples):
    """
    This stores a list of triples in json format, into a RDF file descriptor or stream.
    This is used by dockit when an output file name is specified, instead of an HTTP server.
    This output file receives the events (system function calls) at the end of the execution of dockit.
    TODO: It would be simpler and faster for dockit, to manipulate and generate rdflib data,
    TODO: ... instead of creating triples in JSON then recoding them to rdflib.
    TODO: The idea was to be independent of rdflib, but this is not necessary.
    """
    rdflib_graph = rdflib.Graph()
    for tripl in json_triples:
        rdf_triple = json_triple_to_rdf_triple(*tripl)
        rdflib_graph.add(rdf_triple)
    return rdflib_graph


def json_triples_to_rdf(json_triples, rdf_file_path):
    """
    This stores a list of triples in json format, into a RDF file descriptor or stream.
    This is used by dockit when an output file name is specified, instead of an HTTP server.
    This output file receives the events (system function calls) at the end of the execution of dockit.
    TODO: It would be simpler and faster for dockit, to manipulate and generate rdflib data,
    TODO: ... instead of creating triples in JSON then recoding them to rdflib.
    TODO: The idea was to be independent of rdflib, but this is not necessary.
    """
    rdflib_graph = _json_triples_to_graph(json_triples)
    rdflib_graph.serialize(destination=rdf_file_path, format='xml')

