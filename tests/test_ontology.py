#!/usr/bin/env python

"""Test the generation of ontologies."""

from __future__ import print_function

import unittest
import rdflib
from rdflib.namespace import RDF, RDFS

from init import *

import lib_client
import lib_kbase


def _check_rdf_ontology_conformance(rdf_graph):
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
            dict_domains[the_subject] = the_object
        elif the_predicate == RDFS.label:
            if the_subject in dict_labels:
                errors_list.append("Duplicated label %s => %s" % (the_subject, dict_labels[the_subject]))
            dict_labels[the_subject] = the_object
        elif the_predicate == RDFS.comment:
            # Duplicate comments are allowed.
            dict_comments[the_subject] = the_object
        else:
            non_ontology_graph.add((the_subject, the_predicate, the_object))

    print("")
    print("Classes:", [str(a_class) for a_class in set_classes])
    print("Properties:", [str(a_prop) for a_prop in set_properties])

    for an_object, its_class in dict_objects.items():
        if its_class not in set_classes:
            errors_list.append("Missing class %s for object %s" % (its_class, an_object))

    # The remaining triples must use defined urls.
    for the_subject, the_predicate, the_object in non_ontology_graph:
        if the_predicate not in set_properties:
            errors_list.append("Missing property %s for object %s" % (the_predicate, the_subject))

    return errors_list


class RdfOntologyConformanceSurvolLocaTest(unittest.TestCase):
    """
    These tests do not need a Survol agent because they import directly the module.
    They use all sorts of URL to have a reasonably general coverage.
    """

    def _check_rdf_url_ontology(self, the_content_rdf):
        print("test_create_source_local_rdf: RDF content=%s ..." % str(the_content_rdf)[:30])

        rdf_graph = lib_kbase.triplestore_from_rdf_xml(the_content_rdf)
        errors_list = _check_rdf_ontology_conformance(rdf_graph)
        print("Errors:")
        for one_error in errors_list:
            print("    ", one_error)
        return errors_list

    def test_conformance_file_stat(self):
        """
        This runs a filestat command and checks that the ontology included in the graph is correct.
        """
        my_source_local = lib_client.SourceLocal(
            "sources_types/CIM_DataFile/file_stat.py",
            "CIM_DataFile",
            Name=always_present_file)
        print("test_conformance_file_stat: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

    def test_conformance_enumerate_CIM_LogicalDisk(self):
        """Test of enumerate_CIM_LogicalDisk.py"""
        my_source_local = lib_client.SourceLocal(
            "sources_types/enumerate_CIM_LogicalDisk.py")
        print("test_conformance_enumerate_CIM_LogicalDisk: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_conformance_enumerate_Win32_UserAccount(self):
        """Test of enumerate_Win32_UserAccount.py and corrected of attached ontology"""
        my_source_local = lib_client.SourceLocal(
            "sources_types/win32/enumerate_Win32_UserAccount.py")
        print("test_conformance_enumerate_Win32_UserAccount: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_conformance_win32_NetLocalGroupGetMembers(self):
        """Test of win32_NetLocalGroupGetMembers.py and the correctness of the ontology of classes and attributes."""

        # The group "Users" is always here.
        my_source_local = lib_client.SourceLocal(
            "sources_types/Win32_Group/win32_NetLocalGroupGetMembers.py",
            "Win32_Group",
            Name="Users",
            Domain=CurrentDomainWin32)
        print("test_conformance_win32_NetLocalGroupGetMembers: query=%s" % my_source_local.create_url_query())
        the_content_rdf = my_source_local.content_rdf()
        errors_list = self._check_rdf_url_ontology(the_content_rdf)
        self.assertEqual(errors_list, [])


class RdfOntologyContentCheck(unittest.TestCase):
    """
    This checks the content of the generated ontology depending on the platform.
    """

    def test_conformance_common(self):

        """
            #graph.add((class_CIM_Process, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
            #graph.add((class_CIM_Process, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_Process")))
            #graph.add((class_CIM_Directory, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
            #graph.add((class_CIM_Directory, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_Directory")))
            #graph.add((class_CIM_DataFile, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
            #graph.add((class_CIM_DataFile, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_DataFile")))

            #graph.add((predicate_Handle, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
            #graph.add((predicate_Handle, rdflib.namespace.RDFS.domain, class_CIM_Process))
            #graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))
            #graph.add((predicate_Handle, rdflib.namespace.RDFS.label, rdflib.Literal("Handle")))
            #graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))

            graph.add((predicate_ParentProcessId, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
            graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.domain, class_CIM_Process))
            graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
            graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.label, rdflib.Literal("ParentProcessId")))

            #graph.add((predicate_Name, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
            #graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_Directory))
            #graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_DataFile))
            #graph.add((predicate_Name, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
            #graph.add((predicate_Name, rdflib.namespace.RDFS.label, rdflib.Literal("Name")))

            graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
            graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.domain, class_CIM_Directory))
            graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, class_CIM_DataFile))
            graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, class_CIM_Directory))
            graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
            graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_DirectoryContainsFile")))

            graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
            graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDFS.domain, class_CIM_Process))
            graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDFS.range, class_CIM_DataFile))
            graph.add((associator_CIM_ProcessExecutable, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_ProcessExecutable")))
        """
        pass

