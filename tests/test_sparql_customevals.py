#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import rdflib
import unittest
import psutil

from init import *

update_test_path()

survol_url = "http://primhillcomputer.com/ontologies/"
survol_namespace = rdflib.Namespace(survol_url)
class_CIM_Process = rdflib.term.URIRef(survol_url + "CIM_Process")
class_CIM_Directory = rdflib.term.URIRef(survol_url + "CIM_Directory")
predicate_Handle = rdflib.term.URIRef(survol_url + "Handle")
predicate_Name = rdflib.term.URIRef(survol_url + "Name")


def add_process_to_graph(graph, pid, process_name = None):
    print("Graph id=", id(graph))
    my_process = rdflib.term.URIRef(survol_url + "objects/CIM_Process?Handle=%d" % pid)

    graph.add((my_process, rdflib.namespace.RDF.type, class_CIM_Process))
    graph.add((my_process, predicate_Handle, rdflib.Literal(pid)))
    if not process_name:
        process_name = "Process=%d" % pid
    graph.add((my_process, rdflib.namespace.RDFS.label, rdflib.Literal(process_name)))


def add_directory_to_graph(graph, directory_path):
    print("Graph id=", id(graph))
    my_dir = rdflib.term.URIRef(survol_url + "objects/CIM_Directory?Name=%s" % directory_path)

    graph.add((my_dir, rdflib.namespace.RDF.type, class_CIM_Directory))
    graph.add((my_dir, predicate_Name, rdflib.Literal(directory_path)))



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



class RdflibCustomEvalsProcessesTest(unittest.TestCase):

    # Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
    @staticmethod
    def custom_eval_processes(ctx, part):
        # part.name = "SelectQuery", "Project", "BGP"
        # print("customEval part.name=", part.name)
        if part.name == 'BGP':

            # Iterate over all running process
            for proc in psutil.process_iter():
                try:
                    add_process_to_graph(ctx.graph, proc.pid, proc.name())
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass


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
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_processes'] = RdflibCustomEvalsProcessesTest.custom_eval_processes

    def tearDown(self):
        if 'custom_eval_processes' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_processes']

    def test_query_process(self):
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



if __name__ == '__main__':
    unittest.main()

