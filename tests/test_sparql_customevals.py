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

def add_process_to_graph(graph, pid, process_name = None):
    print("Graph id=", id(graph))
    my_process = rdflib.term.URIRef(survol_url + "objects/CIM_Process?Handle=%d" % pid)

    graph.add((my_process, rdflib.namespace.RDF.type, class_CIM_Process))
    graph.add((my_process, predicate_Handle, rdflib.Literal(pid)))
    if not process_name:
        process_name = "Process=%d" % pid
    graph.add((my_process, rdflib.namespace.RDFS.label, rdflib.Literal(process_name)))
    return my_process


def add_directory_to_graph(graph, directory_path):
    print("Graph id=", id(graph))
    my_dir = rdflib.term.URIRef(survol_url + "objects/CIM_Directory?Name=%s" % directory_path)

    graph.add((my_dir, rdflib.namespace.RDF.type, class_CIM_Directory))
    graph.add((my_dir, predicate_Name, rdflib.Literal(directory_path)))
    return my_dir


def add_datafile_to_graph(graph, file_path):
    print("Graph id=", id(graph))
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
            self.assertTrue( str(one_tuple[0]).startswith('http://primhillcomputer.com/ontologies/objects/CIM_Process?Handle='))

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


def Feeder_CIM_Process(graph, instance_node, instance):
    # Iterate over all running process
    for proc in psutil.process_iter():
        try:
            add_process_to_graph(graph, proc.pid, proc.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def Feeder_CIM_Directory(graph, instance_node, instance):
    try:
        directory_name = instance.m_known_attributes[predicate_Name]
        variable_contained = instance.m_associators[associator_CIM_DirectoryContainsFile]

        for subdir, dirs, files in os.walk(directory_name):
            for file in files:
                filepath = os.path.join(subdir, file)
                file_node = add_datafile_to_graph(graph, filepath, instance_node)
                graph.add((instance_node, associator_CIM_DirectoryContainsFile, file_node))

            for dir in dirs:
                dirpath = os.path.join(subdir, dir)
                directory_node = add_directory_to_graph(graph, dirpath, instance_node)
                graph.add((instance_node, associator_CIM_DirectoryContainsFile, directory_node))

            break
    except KeyError:
        pass

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
                feeders_dict[subject_class](ctx.graph, part_subject, current_instance)


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
                ?url_directory survol:Name "C:/temp" .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))

    def test_query_sub_directories(self):
        rdflib_graph = rdflib.Graph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?directory_name_2 WHERE {
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_1 survol:Name "C:/temp" .
                ?url_directory_2 survol:Name ?directory_name_2 .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)



if __name__ == '__main__':
    unittest.main()

