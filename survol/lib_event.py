"""Stores and retrieves data related to an entity."""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__     = "GPL"

import os
import re
import sys
import six
import time
import json
import string
import lib_common
import lib_util
import lib_kbase
import lib_credentials


def _json_moniker_to_entity_class_and_dict(json_moniker):
    assert len(json_moniker) == 2
    entity_type, entity_attributes_dict = json_moniker
    assert isinstance(entity_type, (six.binary_type, six.text_type))
    assert isinstance(entity_attributes_dict, dict)

    ontology_list = lib_util.OntologyClassKeys(entity_type)

    # TODO: Only the properties we need. In fact, they should come in the right order.
    # TODO: Make this faster by assuming this is a list of key-value pairs.
    entity_ids_dict = {ontology_attribute_name: entity_attributes_dict[ontology_attribute_name]
                       for ontology_attribute_name in ontology_list}
    return entity_type, entity_ids_dict


def store_events_as_json_triples_list(json_data_list):
    rdflib_graph = _json_triples_to_graph(json_data_list)
    return lib_kbase.write_graph_to_events(None, rdflib_graph)


def json_triple_to_rdf_triple(input_json_triple):
    """Transforms a triple in JSON representation, into the rdflib triple.
    This JSON representation of triples, makes that dockit does not need rdflib
    """
    def url_json_to_txt(json_value):
        entity_type, entity_ids_dict = _json_moniker_to_entity_class_and_dict(json_value)

        return lib_common.gUriGen.UriMakeFromDict(entity_type, entity_ids_dict)

    subject_value_json = input_json_triple["subject"]
    subject_value_text = url_json_to_txt(subject_value_json)

    object_value_json = input_json_triple["object"]

    # The object might be another CIM object or a literal.
    # We should check the form: ("string", {})
    if isinstance(object_value_json, tuple) and len(object_value_json) == 2:
        object_value_text = url_json_to_txt(object_value_json)
    else:
        object_value_text = lib_kbase.MakeNodeLiteral(object_value_json)
        #sys.stderr.write("_store_event_triple stored object.\n")

    url_predicate = lib_common.MakeProp(input_json_triple["predicate"])
    rdf_triple = (subject_value_text, url_predicate, object_value_text)
    return rdf_triple


def _json_triples_to_graph(json_triples):
    """
    This stores a list of triples in json format, into a RDF file descriptor or stream.
    This is used by dockit when an output file name is specified, instead of an HTTP server.
    This output file receives the events (system function calls) at the end of the execution of dockit.
    TODO: It would be simpler and faster for dockit, to manipulate and generate rdflib data,
    TODO: ... instead of creating triples in JSON then recoding them to rdflib.
    TODO: The idea was to be independent of rdflib, but this is not necessary.
    """
    rdflib_graph = lib_kbase.MakeGraph()
    for tripl in json_triples:
        rdf_triple = json_triple_to_rdf_triple(tripl)
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
    rdflib_graph.serialize(destination=rdf_file_path, format='pretty-xml')

