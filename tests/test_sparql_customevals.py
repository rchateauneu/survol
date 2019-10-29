#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import rdflib
import unittest

from init import *

update_test_path()

class RdflibCustomEvalsTest(unittest.TestCase):

    def test_sparql_query(self):

        survol_url = "http://primhillcomputer.com/ontologies/"
        survol_namespace = rdflib.Namespace(survol_url)
        class_CIM_Process = rdflib.term.URIRef(survol_url + "CIM_Process")
        class_CIM_Directory = rdflib.term.URIRef(survol_url + "CIM_Directory")
        predicate_Handle = rdflib.term.URIRef(survol_url + "Handle")
        predicate_Name = rdflib.term.URIRef(survol_url + "Name")

        def add_process_to_graph(graph, pid):
            print("Graph id=", id(graph))
            my_process = rdflib.term.URIRef(survol_url + "objects/CIM_Process?Handle=%d" % pid)

            graph.add((my_process, rdflib.namespace.RDF.type, class_CIM_Process))

            graph.add((my_process, predicate_Handle, rdflib.Literal(pid)))

            graph.add((my_process, rdflib.namespace.RDFS.label, rdflib.Literal("Process=%d" % pid)))

        def add_directory_to_graph(graph, directory_path):
            print("Graph id=", id(graph))
            my_process = rdflib.term.URIRef(survol_url + "objects/CIM_Directory?Name=%s" % directory_path)

            graph.add((
                my_process,
                rdflib.namespace.RDF.type,
                class_CIM_Directory))

        # Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
        def customEval(ctx, part):
            # part.name = "SelectQuery", "Project", "BGP"
            # print("customEval part.name=", part.name)
            if part.name == 'BGP':

                print("Part Triples:")
                if False:
                    # query="?url_process a ?url_class ."
                    part_triples = [
                        (
                            rdflib.term.Variable(u'url_process'),
                            rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
                            rdflib.term.Variable(u'url_class')
                        )
                    ]
                    # query="?url_process a survol:CIM_Process ."
                    part_triples2 = [
                        (
                            rdflib.term.Variable(u'url_process'),
                            rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'),
                            rdflib.term.URIRef(u'http://primhillcomputer.com/ontologies/CIM_Process')
                        )
                    ]

                for t in part.triples:
                   print("    ", t)

                if False:
                    print("Ctx=", dir(ctx))
                    ctx_dir = [
                        '__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattribute__', '__getitem__', '__hash__', '__init__', '__module__', '__new__',
                        '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__',
                        '_dataset', '_get_dataset',
                          'bindings', 'bnodes', 'clean', 'clone', 'dataset', 'get', 'graph', 'initBindings', 'load', 'now', 'prologue', 'push', 'pushGraph', 'solution', 'thaw'
                    ]

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
                    print("list_BGP=", list_BGP)
                    if False:
                        list_BGP = [
                            {
                                rdflib.term.Variable(u'url_class'): rdflib.term.URIRef(u'http://primhillcomputer.com/ontologies/classes/CIM_Process'),
                                rdflib.term.Variable(u'url_process'): rdflib.term.URIRef(u'http://primhillcomputer.com/ontologies/objects/CIM_Process?pid=123')
                            }
                        ]
                    return iter(list_BGP)

            raise NotImplementedError()

        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['exampleEval'] = customEval

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

        if 'exampleEval' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['exampleEval']



if __name__ == '__main__':
    unittest.main()

