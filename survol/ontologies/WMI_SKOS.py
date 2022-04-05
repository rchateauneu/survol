#!/usr/bin/env python

"""Displays the WMI classes and attributes of this Windows machine."""

# This creates a SKOS ontology out of the WMI classes of a Windows machine.
# It creates a plain RDF ontology, and converts it by replacing some properties.
# It may not use all the power of SKOS but this is not needed at the moment:
# The need is simply to have a plain SKOS ontology.

# https://stackoverflow.com/questions/24017320/using-owlclass-prefix-with-rdflib-and-xml-serialization

import os
import rdflib
import lib_ontology_tools
import lib_export_ontology
import lib_wmi
import lib_common


def _convert_ontology_to_skos(input_graph):

    all_classes = set()
    derived_classes = set()
    all_properties = set()

    # First pass to get the top classes.
    for rdf_subject, rdf_property, rdf_object in input_graph:
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDFS.Class:
            all_classes.add(rdf_subject)
        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDF.Property:
            all_properties.add(rdf_subject)
        elif rdf_property == rdflib.namespace.RDFS.subClassOf:
            derived_classes.add(rdf_subject)

    top_classes = all_classes - derived_classes

    skos_graph = rdflib.Graph()

    skos = rdflib.Namespace('http://www.w3.org/2004/02/skos/core#')
    skos_graph.bind('skos', skos)

    for rdf_subject, rdf_property, rdf_object in input_graph:
        # if rdf_property == rdflib.namespace.RDF.type:
        #     if rdf_object == rdflib.namespace.XSD.string:
        #         pass
        #     elif rdf_object == rdflib.namespace.XSD.integer:
        #         pass
        #     elif rdf_object == rdflib.namespace.XSD.boolean:
        #         pass
        #     elif rdf_object == rdflib.namespace.XSD.double:
        #         pass
        #     elif rdf_object == rdflib.namespace.XSD.dateTime:
        #         pass
        #     else:
        #         pass
        #     rdf_property = skos_prefix + "Concept"
        # elif rdf_property == rdflib.namespace.RDFS.label:
        #     rdf_property = skos_prefix + "prefLabel"
        # elif rdf_property == rdflib.namespace.RDFS.comment:
        #     rdf_property = skos_prefix + "altLabel"
        # elif rdf_property == rdflib.namespace.RDFS.domain:
        #     pass
        # elif rdf_property == rdflib.namespace.RDFS.range:
        #     pass
        # else:
        #     pass
        #
        # if rdf_object == rdflib.namespace.RDFS.Property:
        #     pass
        # elif rdf_property == rdflib.namespace.RDFS.Class:
        #     pass
        # else:
        #     pass
        # Add the original triple anyway.
        skos_graph.add((rdf_subject, rdf_property, rdf_object))

        if rdf_property == rdflib.namespace.RDF.type and rdf_object == rdflib.namespace.RDFS.Class:
            skos_graph.add((rdf_subject, rdflib.namespace.RDF.type, skos['Concept']))
        elif rdf_property == rdflib.namespace.RDFS.label:
            skos_graph.add((rdf_subject, skos['prefLabel'], rdf_object))
        elif rdf_property == rdflib.namespace.RDFS.comment:
            skos_graph.add((rdf_subject, skos['altLabel'], rdf_object))
        elif rdf_property == rdflib.namespace.RDFS.subClassOf:
            skos_graph.add((rdf_subject, skos['broader'], rdf_object))

    for one_class_node in top_classes:
        skos_graph.add((one_class_node, skos['inScheme'], skos['topConceptOf']))

    # all_properties????

    return skos_graph


"""
    # Add skos:ConceptScheme
    # For each rdfs:Class that you already have, create skos:Concept and:
    #     Map rdfs:label to skos:prefLabel and rdfs:comment to skos:definition
    #     Create skos:broader pointing to rdfs:subClassOf
    #     Set skos:inScheme and skos:topConceptOf for top concepts
    # Do the same for rdfs:Property, although you may need to be selective
"""


def Main():
    try:
        graph = rdflib.Graph()
        lib_ontology_tools.serialize_ontology_to_graph("wmi", lib_wmi.extract_specific_ontology_wmi, graph)
    except Exception as exc:
        lib_common.ErrorMessageHtml("Caught:" + str(exc))

    skos_graph = _convert_ontology_to_skos(graph)

    onto_filnam = os.path.splitext(__file__)[0] + ".rdfs"
    lib_export_ontology.flush_or_save_rdf_graph(skos_graph, onto_filnam)


if __name__ == '__main__':
    Main()
