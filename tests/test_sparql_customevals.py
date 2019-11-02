#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import collections
import rdflib
import unittest
import psutil

from init import *

update_test_path()

survol_url = "http://primhillcomputer.com/ontologies/"
survol_namespace = rdflib.Namespace(survol_url)
class_CIM_Process = rdflib.term.URIRef(survol_url + "CIM_Process")
class_CIM_Directory = rdflib.term.URIRef(survol_url + "CIM_Directory")
class_CIM_DataFile = rdflib.term.URIRef(survol_url + "CIM_DataFile")

predicate_Handle = rdflib.term.URIRef(survol_url + "Handle")
predicate_Name = rdflib.term.URIRef(survol_url + "Name")

associator_CIM_DirectoryContainsFile = rdflib.term.URIRef(survol_url + "CIM_DirectoryContainsFile")


if sys.platform.startswith("linux"):
    TempDirPath = "/tmp"
else:
    TempDirPath = "C:/Windows/temp"

def add_process_to_graph(graph, pid, process_name = None):
    my_process = rdflib.term.URIRef(survol_url + "objects/CIM_Process?Handle=%d" % pid)

    graph.add((my_process, rdflib.namespace.RDF.type, class_CIM_Process))
    graph.add((my_process, predicate_Handle, rdflib.Literal(pid)))
    if not process_name:
        process_name = "Process=%d" % pid
    graph.add((my_process, rdflib.namespace.RDFS.label, rdflib.Literal(process_name)))
    return my_process


def add_directory_to_graph(graph, directory_path):
    #print("add_directory_to_graph adding:", directory_path)
    my_dir = rdflib.term.URIRef(survol_url + "objects/CIM_Directory?Name=%s" % directory_path)

    graph.add((my_dir, rdflib.namespace.RDF.type, class_CIM_Directory))
    graph.add((my_dir, predicate_Name, rdflib.Literal(directory_path)))
    return my_dir


def add_datafile_to_graph(graph, file_path):
    #print("add_datafile_to_graph adding:", file_path)
    my_file = rdflib.term.URIRef(survol_url + "objects/CIM_DataFile?Name=%s" % file_path)

    graph.add((my_file, rdflib.namespace.RDF.type, class_CIM_DataFile))
    graph.add((my_file, predicate_Name, rdflib.Literal(file_path)))
    return my_file



class RdflibCustomEvalsBasicTest(unittest.TestCase):

    # Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
    @staticmethod
    def custom_eval_basic(ctx, part):
        # part.name = "SelectQuery", "Project", "BGP"
        # print("customEval part.name=", part.name)
        if part.name == 'BGP':

            print("Part Triples:")
            for t in part.triples:
                print("    ", t)

            add_process_to_graph(ctx.graph, 456)

            # rewrite triples
            # triples = []
            # for t in part.triples:
            #     if t[1] == rdflib.RDF.type:
            #         bnode = rdflib.BNode()
            #         triples.append((t[0], t[1], bnode))
            #     else:
            #         triples.append(t)

            bnode = rdflib.BNode()

            # <type 'generator'>
            ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
            if False:
                return ret_BGP
            else:
                list_BGP = list(ret_BGP)
                return iter(list_BGP)

        raise NotImplementedError()

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_basic'] = RdflibCustomEvalsBasicTest.custom_eval_basic

    def tearDown(self):
        if 'custom_eval_basic' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_basic']

    def test_query_process(self):
        rdflib_graph = rdflib.Graph()

        add_process_to_graph(rdflib_graph, 123)
        add_directory_to_graph(rdflib_graph, "/tmp")

        query_processes_urls = """
            PREFIX survol: <%s>
            SELECT ?url_process WHERE {
                ?url_process a survol:CIM_Process .
            }
        """ % (survol_namespace)

        # (rdflib.term.URIRef(u'http://primhillcomputer.com/ontologies/classes/CIM_Process'), rdflib.term.URIRef(u'http://primhillcomputer.com/ontologies/objects/CIM_Process?pid=123'))
        query_result = list(rdflib_graph.query(query_processes_urls))
        self.assertTrue(len(query_result) == 2)
        for one_tuple in query_result:
            self.assertTrue( str(one_tuple[0]).startswith(survol_url+'objects/CIM_Process?Handle='))

        add_process_to_graph(rdflib_graph, 789)
        query_result = list(rdflib_graph.query(query_processes_urls))
        self.assertTrue(len(query_result) == 3)

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?process_pid WHERE {
                ?url_process a survol:CIM_Process .
                ?url_process survol:Handle ?process_pid .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        pids_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Pids only=", pids_only)
        self.assertTrue( pids_only == ['123', '456', '789'])

    def test_query_directories(self):
        rdflib_graph = rdflib.Graph()

        for dir_path in ['/tmp','/opt','/proc','/dev']:
            add_directory_to_graph(rdflib_graph, dir_path)

        query_directory_pathes = """
            PREFIX survol: <%s>
            SELECT ?directory_path WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_directory survol:Name ?directory_path .
            }
        """ % (survol_namespace)

        query_pathes_result = list(rdflib_graph.query(query_directory_pathes))

        pathes_only = sorted([ str(one_result[0]) for one_result in query_pathes_result])
        print("Pathes only=", pathes_only)
        self.assertTrue( pathes_only == ['/dev','/opt','/proc','/tmp'])


class Instance:
    def __init__(self, class_name):
        self.m_class_name = class_name[len(survol_url):]
        self.m_associators = {}
        self.m_known_attributes = {}
        self.m_unknown_attributes = {}


def Feeder_CIM_Process(graph, instance):
    # Iterate over all running process
    for proc in psutil.process_iter():
        try:
            add_process_to_graph(graph, proc.pid, proc.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def Feeder_CIM_Directory(graph, instance):
    print("Feeder_CIM_Directory instance=", instance)
    try:
        top_directory_name = instance.m_known_attributes[predicate_Name]
        top_directory_node = add_directory_to_graph(graph, top_directory_name)
        if associator_CIM_DirectoryContainsFile in instance.m_associators:

            print("Feeder_CIM_Directory directory_name=", top_directory_name)
            for subdir, dirs, files in os.walk(top_directory_name):
                print("Feeder_CIM_Directory directory_name=", top_directory_name)
                for file in files:
                    filepath = os.path.join(subdir, file)
                    file_node = add_datafile_to_graph(graph, filepath)
                    graph.add((top_directory_node, associator_CIM_DirectoryContainsFile, file_node))

                for dir in dirs:
                    dirpath = os.path.join(subdir, dir)
                    directory_node = add_directory_to_graph(graph, dirpath)
                    graph.add((top_directory_node, associator_CIM_DirectoryContainsFile, directory_node))
                break
    except KeyError as exc:
        print("Feeder_CIM_Directory failed:", exc)
        pass

def add_ontology(graph):
    graph.add((class_CIM_Process, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_Directory, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_DataFile, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))

    graph.add((predicate_Handle, rdflib.namespace.RDFS.domain, class_CIM_Process))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_Directory))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_DataFile))
    graph.add((predicate_Name, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, class_CIM_Process))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))


feeders_dict = {
    "CIM_Process":Feeder_CIM_Process,
    "CIM_Directory":Feeder_CIM_Directory
}

class RdflibCustomEvalsFeedTest(unittest.TestCase):

    # Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
    @staticmethod
    def custom_eval_feed(ctx, part):
        # part.name = "SelectQuery", "Project", "BGP"
        # print("customEval part.name=", part.name)
        if part.name == 'BGP':
            add_ontology(ctx.graph)

            instances_dict = collections.defaultdict(dict)
            for part_subject, part_predicate, part_object in part.triples:
                if part_predicate == rdflib.namespace.RDF.type:
                    if isinstance(part_subject, rdflib.term.Variable):
                        class_as_str = part_object.toPython()
                        if class_as_str.startswith(survol_url):
                            instances_dict[part_subject] = Instance(class_as_str)

            for part_subject, part_predicate, part_object in part.triples:
                try:
                    current_instance = instances_dict[part_subject]
                except KeyError:
                    continue

                if part_predicate == rdflib.namespace.RDF.type:
                    continue

                if isinstance(part_object, rdflib.term.Variable):
                    if part_object in instances_dict:
                        current_instance.m_associators[part_predicate] = part_object
                    else:
                        current_instance.m_unknown_attributes[part_predicate] = part_object
                elif isinstance(part_object, rdflib.term.URIRef):
                    pass
                elif isinstance(part_object, rdflib.term.Literal):
                    current_instance.m_known_attributes[part_predicate] = part_object
                else:
                    pass

            for part_subject, current_instance in instances_dict.items():
                subject_class = current_instance.m_class_name
                print("Feeding:", part_subject)
                feeders_dict[subject_class](ctx.graph, current_instance)


            # <type 'generator'>
            ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
            return ret_BGP

        raise NotImplementedError()

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_feed'] = RdflibCustomEvalsFeedTest.custom_eval_feed

    def tearDown(self):
        if 'custom_eval_feed' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_feed']

    def test_query_all_processes(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?process_pid WHERE {
                ?url_process a survol:CIM_Process .
                ?url_process survol:Handle ?process_pid .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        pids_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Pids only=", pids_only)
        self.assertTrue( str(os.getpid()) in pids_only )

    def test_query_current_process(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?url_process WHERE {
                ?url_process a survol:CIM_Process .
                ?url_process survol:Handle %d .
            }
        """ % (survol_namespace, os.getpid())

        query_result = list(rdflib_graph.query(query_pids))
        self.assertTrue( len(query_result) == 1 )

    def test_query_directory_unknown(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_directory survol:Name ?directory_name .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))

    def test_query_directory_known(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?url_directory WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_directory survol:Name "%s" .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(query_pids))
        print(query_result)
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == [survol_url+'objects/CIM_Directory?Name='+TempDirPath])

    def test_query_sub_directories(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?directory_name_2 WHERE {
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_1 survol:Name "%s" .
                ?url_directory_2 survol:Name ?directory_name_2 .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(query_pids))
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        for one_name in names_only:
            self.assertTrue(one_name.startswith(TempDirPath))

        #for s, p, o in rdflib_graph:
        #    print(s, p, o)

    def test_query_classes(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT DISTINCT ?url_class WHERE {
                ?url_object a ?url_class .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        print(query_result)

    def test_query_predicates(self):
        rdflib_graph = rdflib.Graph()

        query_predicates = """
            PREFIX survol: <%s>
            SELECT DISTINCT ?url_predicate WHERE {
                ?url_object ?url_predicate survol:CIM_Directory .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_predicates))
        print(query_result)
        for s, p, o in rdflib_graph:
            print(s, p, o)



if __name__ == '__main__':
    unittest.main()

