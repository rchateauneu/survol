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

pav = rdflib.Namespace('http://purl.org/pav/')
survol = rdflib.Namespace('http://www.primhillcomputers.com/survol#')


def _create_properties_hierarchy(skos_graph: rdflib.Graph, input_graph: rdflib.Graph):
    """
    This creates an hierarchy of properties based on their domains.
    :param The two graphes, input and output:
    :return: Nothing
    """

    # Create a concept of class property for each class.
    all_classes = set()
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDFS.Class:
            all_classes.add(rdf_subject)

    classes_to_label = dict()
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDFS.label and rdf_subject in all_classes:
            classes_to_label[rdf_subject] = str(rdf_object)

    classes_to_base_class = dict()
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDFS.subClassOf and rdf_subject in all_classes:
            classes_to_base_class[rdf_subject] = rdf_object

    # Now create one new concept, SKOS-only, for each class, to represent the properties of this class.
    class_to_concept_class = dict()
    for class_node, class_label in classes_to_label.items():
        concept_class_properties_name = class_label + ".SKOS.properties"
        concept_class_properties_node = rdflib.URIRef(survol[concept_class_properties_name])
        class_to_concept_class[class_node] = concept_class_properties_node

        concept_class_properties_label = rdflib.Literal(class_label + " SKOS properties")
        skos_graph.add((concept_class_properties_node, rdflib.namespace.RDFS.label, concept_class_properties_label))

        skos_graph.add((concept_class_properties_node, rdflib.namespace.SKOS.prefLabel, concept_class_properties_label))
        skos_graph.add((concept_class_properties_node, rdflib.namespace.SKOS.altLabel, concept_class_properties_label))

        skos_graph.add((concept_class_properties_node, rdflib.namespace.RDF.type, rdflib.namespace.SKOS.Concept))
        skos_graph.add((concept_class_properties_node, rdflib.namespace.SKOS.inScheme, survol['propertiesScheme']))

    # Here, each class has its SKOS concept.
    print("len(class_to_concept_class)=", len(class_to_concept_class))
    for class_node, concept_class_properties_node in class_to_concept_class.items():
        if class_node in classes_to_base_class:
            base_concept = class_to_concept_class[classes_to_base_class[class_node]]
            skos_graph.add((concept_class_properties_node, rdflib.namespace.SKOS.broader, base_concept))
        else:
            skos_graph.add((concept_class_properties_node, rdflib.namespace.SKOS.topConceptOf, survol['propertiesScheme']))

    # Properties to their class
    all_properties = dict()
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDF.Property:
            all_properties[rdf_subject] = set()

    properties_to_label = dict()
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDFS.label and rdf_subject in all_properties:
            properties_to_label[rdf_subject] = str(rdf_object)

    # Now add the classes.
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDFS.domain and rdf_subject in all_properties:
            all_properties[rdf_subject].add(rdf_object)

    for one_property_node, domain_classes in all_properties.items():
        print("one_property_node", one_property_node)
        for one_domain_class in domain_classes:
            concept_class = class_to_concept_class[one_domain_class]
            # It would be better to have only one base class.
            # TODO: Use only the base class, common to all domains of this property.
            skos_graph.add((one_property_node, rdflib.namespace.SKOS.broader, concept_class))
        property_label = rdflib.Literal(properties_to_label[one_property_node])
        skos_graph.add((one_property_node, rdflib.namespace.SKOS.prefLabel, property_label))
        skos_graph.add((one_property_node, rdflib.namespace.RDF.type, rdflib.namespace.SKOS.Concept))
        skos_graph.add((one_property_node, rdflib.namespace.SKOS.inScheme, survol['propertiesScheme']))


def _convert_ontology_to_skos(input_graph: rdflib.Graph) -> rdflib.Graph:

    skos_graph = rdflib.Graph()

    skos_graph.bind('pav', pav)

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

    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDFS.Class:
            all_classes.add(rdf_subject)
        elif rdf_property == rdflib.namespace.RDFS.subClassOf:
            derived_classes[rdf_subject] = rdf_object

    top_classes = all_classes - set(derived_classes.keys())

    _create_properties_hierarchy(skos_graph, input_graph)

    for derived_class_node, base_class_node in derived_classes.items():
        skos_graph.add((derived_class_node, rdflib.namespace.SKOS.broader, base_class_node))

    for top_class_node in top_classes:
        skos_graph.add((top_class_node, rdflib.namespace.SKOS.topConceptOf, survol['classesScheme']))

    for one_class_node in all_classes:
        skos_graph.add((one_class_node, rdflib.namespace.RDF.type, rdflib.namespace.SKOS.Concept))
        skos_graph.add((one_class_node, rdflib.namespace.SKOS.inScheme, survol['classesScheme']))

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
    lib_export_ontology.flush_or_save_rdf_graph(skos_graph, path_base + "_DUPL.ttl", 'ttl')


if __name__ == '__main__':
    Main()
