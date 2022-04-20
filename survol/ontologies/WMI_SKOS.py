#!/usr/bin/env python

"""Displays the WMI classes and attributes of this Windows machine."""

# This creates a SKOS ontology out of the WMI classes of a Windows machine.
# It creates a plain RDF ontology, and converts it by replacing some properties.
# It may not use all the power of SKOS but this is not needed at the moment:
# The need is simply to have a plain SKOS ontology.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os
import platform

import rdflib

import lib_ontology_tools
import lib_export_ontology
import lib_wmi
import lib_common


def _convert_ontology_to_skos(input_graph):

    skos_graph = rdflib.Graph()

    pav = rdflib.Namespace('http://purl.org/pav/')
    skos_graph.bind('pav', pav)

    survol = rdflib.Namespace('http://www.primhillcomputers.com/survol#')
    skos_graph.bind('survol', survol)

    # Something like '10.0.19041' for Windows 10.
    windows_version = rdflib.Literal(platform.version())

    skos_graph.add((survol['classesScheme'], rdflib.namespace.RDF.type, rdflib.namespace.SKOS.ConceptScheme))
    skos_graph.add((survol['classesScheme'], rdflib.namespace.RDFS.label, rdflib.Literal("WMI Classes")))
    skos_graph.add((survol['classesScheme'], pav['version'], windows_version))
    skos_graph.add((survol['propertiesScheme'], rdflib.namespace.RDF.type, rdflib.namespace.SKOS.ConceptScheme))
    skos_graph.add((survol['propertiesScheme'], rdflib.namespace.RDFS.label, rdflib.Literal("WMI Properties")))
    skos_graph.add((survol['propertiesScheme'], pav['version'], windows_version))

    # First pass to get top classes and derived classes, and all properties.
    all_classes = set()
    derived_classes = dict()
    all_properties = set()

    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDFS.Class:
            all_classes.add(rdf_subject)
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDF.Property:
            all_properties.add(rdf_subject)
        elif rdf_property == rdflib.namespace.RDFS.subClassOf:
            derived_classes[rdf_subject] = rdf_object

    top_classes = all_classes - set(derived_classes.keys())

    for derived_class_node, base_class_node in derived_classes.items():
        skos_graph.add((derived_class_node, rdflib.namespace.SKOS.broader, base_class_node))

    for top_class_node in top_classes:
        skos_graph.add((top_class_node, rdflib.namespace.SKOS.topConceptOf, survol['classesScheme']))

    for one_class_node in all_classes:
        skos_graph.add((one_class_node, rdflib.namespace.RDF.type, rdflib.namespace.SKOS.Concept))
        skos_graph.add((one_class_node, rdflib.namespace.SKOS.inScheme, survol['classesScheme']))

    for one_property_node in all_properties:
        skos_graph.add((one_property_node, rdflib.namespace.RDF.type, rdflib.namespace.SKOS.Concept))
        skos_graph.add((one_property_node, rdflib.namespace.SKOS.topConceptOf, survol['propertiesScheme']))
        skos_graph.add((one_property_node, rdflib.namespace.SKOS.inScheme, survol['propertiesScheme']))

    # Now scan all triples for comments and labels.
    for rdf_subject, rdf_property, rdf_object in input_graph:
        skos_graph.add((rdf_subject, rdf_property, rdf_object))

        if rdf_property == rdflib.namespace.RDFS.label:
            skos_graph.add((rdf_subject, rdflib.namespace.SKOS.prefLabel, rdf_object))
        elif rdf_property == rdflib.namespace.RDFS.comment:
            skos_graph.add((rdf_subject, rdflib.namespace.SKOS.altLabel, rdf_object))

    return skos_graph


def Main():
    try:
        graph = rdflib.Graph()
        lib_ontology_tools.serialize_ontology_to_graph("wmi", lib_wmi.extract_specific_ontology_wmi, graph)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    skos_graph = _convert_ontology_to_skos(graph)

    path_base = os.path.splitext(__file__)[0]

    lib_export_ontology.flush_or_save_rdf_graph(skos_graph, path_base + ".rdfs")

    # Writes the same content in turtle format.
    lib_export_ontology.flush_or_save_rdf_graph(graph, path_base + "_DUPL.ttl", 'ttl')

    graph.namespace_manager.bind('survol', rdflib.Namespace('http://www.primhillcomputers.com/survol#'), override=True)
    lib_export_ontology.flush_or_save_rdf_graph(graph, path_base + "_DUPL_BIND.ttl", 'ttl')

    g = rdflib.Graph()
    g.parse(path_base + ".rdfs", format='xml')
    g.namespace_manager.bind('survol', rdflib.Namespace('http://www.primhillcomputers.com/survol#'), override=True)
    g.serialize(destination=path_base + "_RELOAD.ttl", format='turtle')


if __name__ == '__main__':
    Main()
