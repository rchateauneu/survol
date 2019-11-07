#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import collections
import tempfile
import rdflib
import rdflib.plugins.memory
import unittest
import psutil

from init import *

update_test_path()

################################################################################

# Sparql does not like backslashes.
TempDirPath = tempfile.gettempdir().replace("\\","/")

def create_temp_file():
    tmp_filename = "survol_temp_file_%d.tmp" % os.getpid()
    tmp_pathname = os.path.join(TempDirPath, tmp_filename)
    tmpfil = open(tmp_pathname, "w")
    tmpfil.close()
    return tmp_pathname


################################################################################

class SurvolStore(rdflib.plugins.memory.IOMemory):
    def __init__(self, configuration=None, identifier=None):
        super(SurvolStore, self).__init__(configuration)

    def triples(self, subject, predicate, object, context=None):
        print("triples=",subject, predicate, object)
        if context:
            print("context=",context)
        return super(SurvolStore, self).triples((subject, predicate, object), context)

def CreateGraph():
    survol_store = SurvolStore()
    rdflib_graph = rdflib.Graph(survol_store)

    return rdflib_graph

################################################################################

survol_url = "http://primhillcomputer.com/ontologies/"
survol_namespace = rdflib.Namespace(survol_url)
class_CIM_Process = rdflib.term.URIRef(survol_url + "CIM_Process")
class_CIM_Directory = rdflib.term.URIRef(survol_url + "CIM_Directory")
class_CIM_DataFile = rdflib.term.URIRef(survol_url + "CIM_DataFile")

predicate_Handle = rdflib.term.URIRef(survol_url + "Handle")
predicate_Name = rdflib.term.URIRef(survol_url + "Name")

associator_CIM_DirectoryContainsFile = rdflib.term.URIRef(survol_url + "CIM_DirectoryContainsFile")


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

################################################################################

class RdflibCustomEvalsBasicTest(unittest.TestCase):
    "Simple test of a custom evals functions."

    # Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
    @staticmethod
    def custom_eval_basic(ctx, part):
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
        rdflib_graph = CreateGraph()

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
        rdflib_graph = CreateGraph()

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

################################################################################


class RdflibIndividualCustomEvalsTest(unittest.TestCase):
    """Several custom eval funtions, called if failing."""

    must_raise_one = False
    must_raise_two = False
    was_called_one = False
    was_called_two = False

    @staticmethod
    def reset_flags(one, two):
        RdflibIndividualCustomEvalsTest.must_raise_one = one
        RdflibIndividualCustomEvalsTest.must_raise_two = two
        RdflibIndividualCustomEvalsTest.was_called_one = False
        RdflibIndividualCustomEvalsTest.was_called_two = False

    @staticmethod
    def custom_eval_one(ctx, part):
        if part.name == 'BGP':
            print("Calling custom_eval_one:")
            if RdflibIndividualCustomEvalsTest.must_raise_one:
                raise NotImplementedError()

            RdflibIndividualCustomEvalsTest.was_called_one = True
            print("Inside custom_eval_one:")
            return rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)

        raise NotImplementedError()

    @staticmethod
    def custom_eval_two(ctx, part):
        if part.name == 'BGP':
            print("Calling custom_eval_two:")
            if RdflibIndividualCustomEvalsTest.must_raise_two:
                raise NotImplementedError()

            RdflibIndividualCustomEvalsTest.was_called_two = True
            print("Inside custom_eval_two:")
            return rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)

        raise NotImplementedError()

    def test_query_several_custom_evals(self):
        """
        This tests the logic of several custom eval functions.
        """
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_one'] = RdflibIndividualCustomEvalsTest.custom_eval_one
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_two'] = RdflibIndividualCustomEvalsTest.custom_eval_two

        rdflib_graph = CreateGraph()

        add_process_to_graph(rdflib_graph, 123)
        add_directory_to_graph(rdflib_graph, "/tmp")

        query_processes_urls = """
            PREFIX survol: <%s>
            SELECT ?url_process WHERE {
                ?url_process a survol:CIM_Process .
            }
        """ % (survol_namespace)

        RdflibIndividualCustomEvalsTest.reset_flags(False, False)
        rdflib_graph.query(query_processes_urls)
        self.assertTrue(RdflibIndividualCustomEvalsTest.was_called_one)
        self.assertFalse(RdflibIndividualCustomEvalsTest.was_called_two)

        RdflibIndividualCustomEvalsTest.reset_flags(True, False)
        rdflib_graph.query(query_processes_urls)
        self.assertFalse(RdflibIndividualCustomEvalsTest.was_called_one)
        self.assertTrue(RdflibIndividualCustomEvalsTest.was_called_two)

        RdflibIndividualCustomEvalsTest.reset_flags(False, True)
        rdflib_graph.query(query_processes_urls)
        self.assertTrue(RdflibIndividualCustomEvalsTest.was_called_one)
        self.assertFalse(RdflibIndividualCustomEvalsTest.was_called_two)

        RdflibIndividualCustomEvalsTest.reset_flags(True, True)
        rdflib_graph.query(query_processes_urls)
        self.assertFalse(RdflibIndividualCustomEvalsTest.was_called_one)
        self.assertFalse(RdflibIndividualCustomEvalsTest.was_called_two)

        del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_one']
        del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_two']

################################################################################


class RdflibCombinedCustomEvalsTest(unittest.TestCase):
    """
    Several custom eval funtions, called if failing.
    Each of them can still add data.
    """


    def test_query_several_custom_evals(self):
        "This tests the logic of several custom eval functions."

        def custom_eval_one(ctx, part):
            if part.name == 'BGP':
                print("Calling custom_eval_one:")
                add_process_to_graph(ctx.graph, 111)
                raise NotImplementedError()

            raise NotImplementedError()

        def custom_eval_two(ctx, part):
            if part.name == 'BGP':
                print("Calling custom_eval_two:")
                add_process_to_graph(ctx.graph, 222)
                return rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)

            raise NotImplementedError()

        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_one'] = custom_eval_one
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_two'] = custom_eval_two

        rdflib_graph = CreateGraph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?handle_process WHERE {
                ?url_process a survol:CIM_Process .
                ?url_process survol:Handle ?handle_process .
            }
        """ % (survol_namespace)


        iter_result = rdflib_graph.query(sparql_query)
        query_result = list(iter_result)
        pids_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Pids only=", pids_only)
        self.assertTrue( pids_only == ['111', '222'])

        del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_one']
        del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_two']

################################################################################


class ObjectInstance:
    def __init__(self, class_name, key_variable):
        self.m_variable = key_variable
        self.m_class_name = class_name[len(survol_url):]
        self.m_associators = {}
        self.m_known_attributes = {}
        self.m_unknown_attributes = {}
        self.m_see_also = []
        self.m_input_variables = []

    def Feed(self, graph, variables_context):
        subject_class = self.m_class_name
        # TODO: Return a function instead of looping twice.
        it = survol_feeders_dict[subject_class](graph, self)
        for elt in it:
            yield elt

        if "WMI" in self.m_see_also:
            raise NotImplementedError("Not implemented yet")
            wmi_feeder(graph, self)

        if "WBEM" in self.m_see_also:
            raise NotImplementedError("Not implemented yet")
            wbem_feeder(graph, self)

    def __str__(self):
        def kw_to_str(property, value):
            property_str = str(property)[len(survol_url):]
            value_str = str(value)
            return "%s=%s" % (property_str, value_str)

        # print("ka=", self.m_known_attributes.items())
        kw = ".".join([ kw_to_str(property, value) for property, value in self.m_known_attributes.items()])
        vars_str = ",".join( str(var) for var in self.m_input_variables)
        return "ObjectInstance:" + self.m_class_name + ":" + self.m_variable + ":" + kw + ":" + vars_str

# BEWARE: The built-in sort method requires that cmp imposes a total ordering,
# BEWARE: ... which is not the case here.
def compare_instances(instance_a, instance_b):
    a_from_b = instance_a.m_variable in instance_b.m_input_variables
    b_from_a = instance_b.m_variable in instance_a.m_input_variables
    if a_from_b:
        return 0 if b_from_a else 1
    else:
        return -1 if b_from_a else 0

def instances_sort(instance_list):
    # https://www.geeksforgeeks.org/python-program-for-topological-sorting/
    from collections import defaultdict

    # If this is an iterator.
    if not isinstance(instance_list, list):
        instance_list = list(instance_list)

    # Class to represent a graph
    class Graph:
        def __init__(self, vertices):
            self.graph = defaultdict(list)  # dictionary containing adjacency List
            self.V = vertices  # No. of vertices

        # function to add an edge to graph
        def addEdge(self, u, v):
            self.graph[u].append(v)

        def topologicalSortUtil(self, v, visited, stack):
            visited[v] = True
            for i in self.graph[v]:
                if visited[i] == False:
                    self.topologicalSortUtil(i, visited, stack)
            stack.insert(0, v)

        def topologicalSort(self):
            visited = [False] * self.V
            stack = []
            for i in range(self.V):
                if visited[i] == False:
                    self.topologicalSortUtil(i, visited, stack)
            return stack

    len_instances = len(instance_list)
    g = Graph(len_instances)
    for one_index in range(len_instances):
        one_instance = instance_list[one_index]
        for another_index in range(len_instances):
            if one_index != another_index:
                another_instance = instance_list[another_index]
                cmp_result = compare_instances(one_instance, another_instance)
                if cmp_result > 0:
                    g.addEdge(one_index, another_index)
                elif cmp_result < 0:
                    g.addEdge(another_index, one_index)
    result_indices = g.topologicalSort()
    result_instances = []
    for one_index in result_indices:
        result_instances.append(instance_list[one_index])
    return result_instances

def part_triples_to_instances_dict(part):
    instances_dict = dict()
    print("Triples")
    for part_subject, part_predicate, part_object in part.triples:
        print("    ", part_subject, part_predicate, part_object)
        if part_predicate == rdflib.namespace.RDF.type:
            if isinstance(part_subject, rdflib.term.Variable):
                class_as_str = part_object.toPython()
                if class_as_str.startswith(survol_url):
                    instances_dict[part_subject] = ObjectInstance(class_as_str, part_subject)

    for part_subject, part_predicate, part_object in part.triples:
        try:
            current_instance = instances_dict[part_subject]
            assert isinstance(current_instance, ObjectInstance)
        except KeyError:
            continue

        if part_predicate == rdflib.namespace.RDF.type:
            continue

        if part_predicate == rdflib.namespace.RDFS.seeAlso:
            current_instance.m_see_also.append(part_object)

        if isinstance(part_object, rdflib.term.Variable):
            try:
                part_object_instance = instances_dict[part_object]
                #current_instance.m_input_variables.append(part_object)

                # Dans quel sens est la dependance ???? Peut tre qu il ny en a pas si Survol.

                part_object_instance.m_input_variables.append(part_subject)
                # Maybe we should store the variable name in the instance.
                current_instance.m_associators[part_predicate] = part_object_instance
            except KeyError:
                current_instance.m_input_variables.append(part_object)
                current_instance.m_unknown_attributes[part_predicate] = part_object
        elif isinstance(part_object, rdflib.term.URIRef):
            pass
        elif isinstance(part_object, rdflib.term.Literal):
            current_instance.m_known_attributes[part_predicate] = part_object
        else:
            pass

    return instances_dict

# Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
def custom_eval_feed(ctx, part):
    # part.name = "SelectQuery", "Project", "BGP"
    # print("customEval part.name=", part.name)
    if part.name == 'BGP':
        add_ontology(ctx.graph)

        instances_dict = part_triples_to_instances_dict(part)

        sorted_instances = instances_sort(instances_dict.values())

        #sorted_instances = sorted(instances_dict.values(), key=functools.cmp_to_key(compare_instances))

        print("Ordered instances")
        for current_instance in sorted_instances:
            print("    ", current_instance.m_variable, current_instance)

        variables_context = dict()

        print("Num instances:", len(sorted_instances))
        def call_one_level(instance_index):
            if instance_index == len(sorted_instances):
                return

            current_instance = sorted_instances[instance_index]
            print("instance_index=", instance_index, current_instance)

            iter_nodes = current_instance.Feed(ctx.graph, variables_context)

            for one_node in iter_nodes:
                variables_context[current_instance.m_variable] = one_node
                call_one_level(instance_index+1)

        call_one_level(instance_index = 0)

        # <type 'generator'>
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP

    raise NotImplementedError()


def wmi_feeder(graph, instance):
    pass

def wbem_feeder(graph, instance):
    pass
################################################################################


def Feeder_CIM_Process(graph, instance):
    # Iterate over all running process
    for proc in psutil.process_iter():
        try:
            yield add_process_to_graph(graph, proc.pid, proc.name())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def Feeder_CIM_Directory(graph, instance):
    print("Feeder_CIM_Directory ", instance)

    # This creates the triple of the directory if its name is known.
    try:
        top_directory_name = instance.m_known_attributes[predicate_Name]
        top_directory_node = add_directory_to_graph(graph, top_directory_name)
        yield top_directory_node
    except KeyError as exc:
        print("Feeder_CIM_Directory No name", exc)
        top_directory_node = None

    try:
        associator_instance = instance.m_associators[associator_CIM_DirectoryContainsFile]
    except KeyError as exc:
        print("Feeder_CIM_Directory No associator", exc)
        return

    if top_directory_node:
        # TODO: Check that the object is a variable.
        # Checks that its class is CIM_DataFile or CIM_Directory and do not take all objects.
        # if associator_CIM_DirectoryContainsFile in instance.m_associators:
        # This is associated to a rdflib.term.Variable
        assert isinstance(associator_instance, ObjectInstance)

        print("Feeder_CIM_Directory directory_name=", top_directory_name)
        for current_subdir, dirs, files in os.walk(top_directory_name):
            print("Feeder_CIM_Directory directory_name=", top_directory_name)

            if associator_instance.m_class_name == "CIM_DataFile":
                for sub_file in files:
                    sub_file_path = os.path.join(current_subdir, sub_file)
                    file_node = add_datafile_to_graph(graph, sub_file_path)
                    graph.add((top_directory_node, associator_CIM_DirectoryContainsFile, file_node))
                    yield file_node
            elif associator_instance.m_class_name == "CIM_Directory":
                for sub_dir in dirs:
                    sub_dir_path = os.path.join(current_subdir, sub_dir)
                    directory_node = add_directory_to_graph(graph, sub_dir_path)
                    graph.add((top_directory_node, associator_CIM_DirectoryContainsFile, directory_node))
                    yield directory_node
            else:
                raise Exception("Invalid class in associator:%s" %  associator_instance.m_class_name)
            break
    else:
        print("Feeder_CIM_Directory associator but no name:")
        try:
            file_path = associator_instance.m_known_attributes[predicate_Name]
            if associator_instance.m_class_name == "CIM_DataFile":
                file_node = add_datafile_to_graph(graph, file_path)
            elif associator_instance.m_class_name == "CIM_DataFile":
                file_node = add_directory_to_graph(graph, file_path)
            else:
                raise Exception("Invalid class in associator (2):%s" % associator_instance.m_class_name)
            parent_path = os.path.dirname(file_path)
            directory_node = add_directory_to_graph(graph, parent_path)
            graph.add((directory_node, associator_CIM_DirectoryContainsFile, file_node))
            yield directory_node

        except KeyError as exc:
            print("Feeder_CIM_Directory failed:", exc, " associated instance not defined:", instance)


def Feeder_CIM_DataFile(graph, instance):
    print("Feeder_CIM_DataFile ", instance)
    try:
        file_path = instance.m_known_attributes[predicate_Name]
        yield add_datafile_to_graph(graph, file_path)
    except KeyError as exc:
        print("Feeder_CIM_DataFile failed:", exc, instance)

survol_feeders_dict = {
    "CIM_Process":Feeder_CIM_Process,
    "CIM_Directory":Feeder_CIM_Directory,
    "CIM_DataFile": Feeder_CIM_DataFile
}

################################################################################
def add_ontology(graph):
    graph.add((class_CIM_Process, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_Process, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_Process")))
    graph.add((class_CIM_Directory, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_Directory, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_Directory")))
    graph.add((class_CIM_DataFile, rdflib.namespace.RDF.type, rdflib.namespace.RDFS.Class))
    graph.add((class_CIM_DataFile, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_DataFile")))

    graph.add((predicate_Handle, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.domain, class_CIM_Process))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))
    graph.add((predicate_Handle, rdflib.namespace.RDFS.label, rdflib.Literal("Handle")))

    graph.add((predicate_Name, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_Directory))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_DataFile))
    graph.add((predicate_Name, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((predicate_Name, rdflib.namespace.RDFS.label, rdflib.Literal("Name")))

    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, class_CIM_Process))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((associator_CIM_DirectoryContainsFile, rdflib.namespace.RDFS.label, rdflib.Literal("CIM_DirectoryContainsFile")))


################################################################################

class RdflibCustomEvalsFeedTest(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_feed'] = custom_eval_feed

    def tearDown(self):
        if 'custom_eval_feed' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_feed']

    def test_query_all_processes(self):
        rdflib_graph = CreateGraph()

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
        rdflib_graph = CreateGraph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?url_process WHERE {
                ?url_process a survol:CIM_Process .
                ?url_process survol:Handle %d .
            }
        """ % (survol_namespace, os.getpid())

        query_result = list(rdflib_graph.query(query_pids))
        self.assertTrue( len(query_result) == 1 )

    @unittest.skip("This cannot work because we cannot return all directories.")
    def test_query_directory_unknown(self):
        rdflib_graph = CreateGraph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_directory survol:Name ?directory_name .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))

    def test_query_directory_known(self):
        rdflib_graph = CreateGraph()

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
        """Subdirectories of temp"""
        rdflib_graph = CreateGraph()

        query_subdirs = """
            PREFIX survol: <%s>
            SELECT ?directory_name_2 WHERE {
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_1 survol:Name "%s" .
                ?url_directory_2 survol:Name ?directory_name_2 .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(query_subdirs))
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        for one_name in names_only:
            self.assertTrue(one_name.startswith(TempDirPath))
            self.assertTrue(os.path.isdir(one_name))

    def test_query_sub_files(self):
        """Subfiles of temp"""
        rdflib_graph = CreateGraph()

        query_subdirs = """
            PREFIX survol: <%s>
            SELECT ?file_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_directory survol:Name "%s" .
                ?url_datafile survol:Name ?file_name .
            }
        """ % (survol_namespace, TempDirPath)

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        query_result = list(rdflib_graph.query(query_subdirs))
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        for one_name in names_only:
            self.assertTrue(one_name.startswith(TempDirPath))
            self.assertFalse(os.path.isdir(one_name))
        self.assertTrue(tmp_pathname in names_only)

    def test_query_sub_directories_and_files(self):
        """Subdirectories and subfiles of temp"""
        rdflib_graph = CreateGraph()

        query_subs = """
            PREFIX survol: <%s>
            SELECT ?result_name
            WHERE {
            {
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_1 survol:Name "%s" .
                ?url_directory_2 survol:Name ?result_name .
            }
            UNION {
                ?url_directory_1 a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_directory_1 survol:Name "%s" .
                ?url_datafile survol:Name ?result_name .
            }
            }
        """ % (survol_namespace, TempDirPath, TempDirPath)

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        query_result = list(rdflib_graph.query(query_subs))
        names_only = sorted([str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        for one_name in names_only:
            self.assertTrue(one_name.startswith(TempDirPath))
        self.assertTrue(tmp_pathname in names_only)

    def test_query_parent_directory(self):
        """Subdirectories of temp"""
        rdflib_graph = CreateGraph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

        query_subdirs = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_directory survol:Name ?directory_name .
                ?url_datafile survol:Name "%s" .
            }
        """ % (survol_namespace, tmp_pathname)

        query_result = list(rdflib_graph.query(query_subdirs))
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == [TempDirPath])

    @unittest.skip("Not yet OK")
    def test_query_grandparent_directory(self):
        """Subdirectories of temp"""
        rdflib_graph = CreateGraph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

        query_subdirs = """
            PREFIX survol: <%s>
            SELECT ?grandparent_name WHERE {
                ?url_grandparent a survol:CIM_Directory .
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_grandparent survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_directory .
                ?url_grandparent survol:Name ?grandparent_name .
                ?url_directory survol:Name ?directory_name .
                ?url_datafile survol:Name "%s" .
            }
        """ % (survol_namespace, tmp_pathname)

        query_result = list(rdflib_graph.query(query_subdirs))
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == [os.path.dirname(TempDirPath)])

    def test_query_all_classes(self):
        rdflib_graph = CreateGraph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT DISTINCT ?url_object WHERE {
                ?url_object a ?url_class .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        print("test_query_all_classes query_result=", query_result)
        names_only = sorted([ str(one_result[0])[len(survol_url):] for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == ['CIM_DataFile', 'CIM_Directory', 'CIM_DirectoryContainsFile', 'CIM_Process', 'Handle', 'Name'])

    def test_query_rdfs_classes(self):
        rdflib_graph = CreateGraph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT DISTINCT ?url_object WHERE {
                ?url_object a rdfs:Class .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        print(query_result)
        names_only = sorted([ str(one_result[0])[len(survol_url):] for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == ['CIM_DataFile', 'CIM_Directory', 'CIM_Process'])

    def test_query_all_predicates_cim_directory(self):
        rdflib_graph = CreateGraph()

        query_properties = """
            PREFIX survol: <%s>
            SELECT DISTINCT ?url_object WHERE {
                ?url_object ?url_property survol:CIM_Directory .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_properties))
        print(query_result)
        names_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == [survol_url+'Name'])

    def test_property_meta_information(self):
        """
        Taken from http://sparql-playground.sib.swiss/faq with no change.
        """
        rdflib_graph = CreateGraph()
        query_meta_information = """
            SELECT DISTINCT ?property
            WHERE { 
              ?property a rdf:Property. 
              optional {?property rdfs:comment ?comment}
              optional {?property rdfs:range ?range}
              optional {?property rdfs:domain ?domain}
              optional {?property rdfs:label ?label}
            }"""
        query_result = list(rdflib_graph.query(query_meta_information))
        print(query_result)
        names_only = sorted([ str(one_result[0])[len(survol_url):] for one_result in query_result])
        print("Names only=", names_only)
        self.assertTrue(names_only == ['CIM_DirectoryContainsFile', 'Handle', 'Name'])


################################################################################

class RdflibCustomEvalsSeeAlsoTest(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_feed'] = custom_eval_feed

    def tearDown(self):
        if 'custom_eval_feed' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_feed']

    @unittest.skip("NOT YET")
    def test_query_all_processes(self):
        rdflib_graph = CreateGraph()

        query_pids = """
            PREFIX survol: <%s>
            SELECT ?process_pid WHERE {
                ?url_process a survol:CIM_Process .
                ?url_process survol:Handle ?process_pid .
                ?url_process rdfs:seeAlso "WMI" .
            }
        """ % (survol_namespace)

        query_result = list(rdflib_graph.query(query_pids))
        pids_only = sorted([ str(one_result[0]) for one_result in query_result])
        print("Pids only=", pids_only)
        self.assertTrue( str(os.getpid()) in pids_only )


################################################################################

class RdflibCustomEvalsUnitTest(unittest.TestCase):

    def test_instances_comparison(self):
        all_instances = []
        instance_a = ObjectInstance("A","var_a")
        instance_a.m_input_variables = ["var_d"]
        all_instances.append(instance_a)

        instance_b = ObjectInstance("B","var_b")
        instance_b.m_input_variables = ["var_a", "var_c"]
        all_instances.append(instance_b)

        instance_c = ObjectInstance("C","var_c")
        instance_c.m_input_variables = ["var_a"]
        all_instances.append(instance_c)

        instance_d = ObjectInstance("D","var_d")
        instance_d.m_input_variables = []
        all_instances.append(instance_d)

        self.assertTrue( compare_instances(instance_a, instance_a) == 0 )
        self.assertTrue( compare_instances(instance_a, instance_b) == 1 )
        self.assertTrue( compare_instances(instance_a, instance_c) == 1 )
        self.assertTrue( compare_instances(instance_a, instance_d) == -1 )

        self.assertTrue( compare_instances(instance_b, instance_a) == -1 )
        self.assertTrue( compare_instances(instance_b, instance_b) == 0 )
        self.assertTrue( compare_instances(instance_b, instance_c) == -1 )
        self.assertTrue( compare_instances(instance_b, instance_d) == 0 )

        self.assertTrue( compare_instances(instance_c, instance_a) == -1 )
        self.assertTrue( compare_instances(instance_c, instance_b) == 1 )
        self.assertTrue( compare_instances(instance_c, instance_c) == 0 )
        self.assertTrue( compare_instances(instance_c, instance_d) == 0 )

        self.assertTrue( compare_instances(instance_d, instance_a) == 1 )
        self.assertTrue( compare_instances(instance_d, instance_b) == 0 )
        self.assertTrue( compare_instances(instance_d, instance_c) == 0 )
        self.assertTrue( compare_instances(instance_d, instance_d) == 0 )

        sorted_instances = instances_sort(all_instances)

        print("")
        print("sorted_instances=",sorted_instances)
        variables_list = [ one_instance.m_variable for one_instance in sorted_instances ]
        print("variables_list=", variables_list)
        self.assertTrue(variables_list == ["var_d","var_a","var_c","var_b"])







################################################################################

class EvalBGP:
    class Instance:
        def __init__(self, ctx, part):
            self.m_associators_left
            self.m_associators_right

        def Clone(self, ctx):
            instance_copy = self.copy()
            return instance_copy

        def Feed(self):
            pass

    def __init__(self, ctx, part):
        self.m_ctx = ctx
        self.m_part = part

    def create_instances_from_part_triples(self, part):
        instances_dict = dict()
        print("Triples")
        for part_subject, part_predicate, part_object in part.triples:
            print("    ", part_subject, part_predicate, part_object)
            if part_predicate == rdflib.namespace.RDF.type:
                if isinstance(part_subject, rdflib.term.Variable):
                    class_as_str = part_object.toPython()
                    if class_as_str.startswith(survol_url):
                        instances_dict[part_subject] = ObjectInstance(class_as_str, part_subject)

        for part_subject, part_predicate, part_object in part.triples:
            try:
                current_instance = instances_dict[part_subject]
                assert isinstance(current_instance, ObjectInstance)
            except KeyError:
                continue

            if part_predicate == rdflib.namespace.RDF.type:
                continue

            if part_predicate == rdflib.namespace.RDFS.seeAlso:
                current_instance.m_see_also.append(part_object)

            if isinstance(part_object, rdflib.term.Variable):
                try:
                    part_object_instance = instances_dict[part_object]
                    # current_instance.m_input_variables.append(part_object)

                    # Dans quel sens est la dependance ???? Peut tre qu il ny en a pas si Survol.

                    part_object_instance.m_input_variables.append(part_subject)
                    # Maybe we should store the variable name in the instance.
                    current_instance.m_associators[part_predicate] = part_object_instance
                except KeyError:
                    current_instance.m_input_variables.append(part_object)
                    current_instance.m_unknown_attributes[part_predicate] = part_object
            elif isinstance(part_object, rdflib.term.URIRef):
                pass
            elif isinstance(part_object, rdflib.term.Literal):
                current_instance.m_known_attributes[part_predicate] = part_object
            else:
                pass

        return instances_dict

    def feed_instance_from_context(self, node, context):
        properties_known = dict()
        properties_unknown = dict()
        # When the node is a subject of an associator.
        right_associators = list()
        # When the node is an object of an associator.

        # Does the variables replacement.
        bound_triples = list()
        for unbound_subject, unbound_property, unbound_subject in self.m_part.triples:
            def bind_from_context(node):
                if isinstance(node, rdflib.term.Variable):
                    try:
                        return context[node]
                    except:
                        return node
                return node

            part_subject = bind_from_context(unbound_subject)
            part_property = bind_from_context(unbound_property)
            part_object = bind_from_context(unbound_subject)
            bound_triples.append((part_subject, part_property, part_object))

        # If nodes are not a known class, cannot do anything.
        nodes_to_class = dict()
        for part_subject, part_property, part_object in bound_triples:
            # An instance might belong to several classes, so take the last one.
            if part_property == rdflib.namespace.RDF.type:
                nodes_to_class[part_subject] = part_property

        if node not in nodes_to_class:
            return

        left_associators = dict()
        for part_subject, part_property, part_object in self.m_part.triples:
            if part_subject == node:
                if part_property == rdflib.namespace.RDF.type:
                    continue
                if isinstance(part_property, rdflib.term.Variable):
                    continue

                if isinstance(part_object, rdflib.term.Variable):
                    # The same property might occur several times but we do not care.
                    # It might be an associator
                    properties_unknown[part_property] = part_object
                elif isinstance(part_object, rdflib.term.Literal):
                    # The same property might occur several times but we do not care.
                    properties_known[part_property] = part_object
                elif isinstance(part_object, rdflib.term.RefURL):
                    right_associators[part_property] = part_object

                    properties_known[part_property] = part_object
                else:
                    print("Unknown type for property and object:", part_object)
            elif part_object == node:
                if part_subject in nodes_to_class:
                    left_associators[part_property] = part_subject


        if isinstance(node, rdflib.term.Variable):
            pass
        else:
            fill_remaining_properties(node, node_class, properties_known, properties_unknown)

        for part_subject, part_predicate, part_object in part.triples:
            try:
                current_instance = instances_dict[part_subject]
                assert isinstance(current_instance, ObjectInstance)
            except KeyError:
                continue

            if part_predicate == rdflib.namespace.RDF.type:
                continue

            if part_predicate == rdflib.namespace.RDFS.seeAlso:
                current_instance.m_see_also.append(part_object)

            if isinstance(part_object, rdflib.term.Variable):
                try:
                    part_object_instance = instances_dict[part_object]
                    # current_instance.m_input_variables.append(part_object)

                    # Dans quel sens est la dependance ???? Peut tre qu il ny en a pas si Survol.

                    part_object_instance.m_input_variables.append(part_subject)
                    # Maybe we should store the variable name in the instance.
                    current_instance.m_associators[part_predicate] = part_object_instance
                except KeyError:
                    current_instance.m_input_variables.append(part_object)
                    current_instance.m_unknown_attributes[part_predicate] = part_object
            elif isinstance(part_object, rdflib.term.URIRef):
                pass
            elif isinstance(part_object, rdflib.term.Literal):
                current_instance.m_known_attributes[part_predicate] = part_object
            else:
                pass

        return instances_dict

    def evalBGP_replacement(self, ctx, bgp):
        if not bgp:
            return [ctx.solution()]

        res = []
        s, p, o = bgp[0]

        try:
            current_instance = self.feed_instance_from_context(s, ctx)

            # If s in ctx[], alors calculer toutes les valeurs de current_instance,
            # et aussi les associators.

            # If s in not in ctx, alors on ne connait pas la valeur:
            # Faire une requete avec les valeurs connues.
            # Idem les associators a gauche et a droite.


        except KeyError:
            pass


        _s = ctx[s]
        _p = ctx[p]
        _o = ctx[o]

        for ss, sp, so in ctx.graph.triples((_s, _p, _o)):
            try:
                if None in (_s, _p, _o):
                    ctx.push()

                if _s is None:
                    ctx[s] = ss

                try:
                    if _p is None:
                        ctx[p] = sp
                except rdflib.plugins.sparql.AlreadyBound:
                    continue

                try:
                    if _o is None:
                        ctx[o] = so
                except rdflib.plugins.sparql.AlreadyBound:
                    continue

                res += self.evalBGP_replacement(ctx, bgp[1:])

            finally:
                if None in (_s, _p, _o):
                    ctx.pop()

    # Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
    def internal_eval_bgp(self, ctx, part):
        add_ontology(ctx.graph)

        """
        instances_dict = part_triples_to_instances_dict(part)

        sorted_instances = instances_sort(instances_dict.values())

        # sorted_instances = sorted(instances_dict.values(), key=functools.cmp_to_key(compare_instances))

        print("Ordered instances")
        for current_instance in sorted_instances:
            print("    ", current_instance.m_variable, current_instance)

        variables_context = dict()

        print("Num instances:", len(sorted_instances))

        def call_one_level(instance_index):
            if instance_index == len(sorted_instances):
                return

            current_instance = sorted_instances[instance_index]
            print("instance_index=", instance_index, current_instance)

            iter_nodes = current_instance.Feed(ctx.graph, variables_context)

            for one_node in iter_nodes:
                variables_context[current_instance.m_variable] = one_node
                call_one_level(instance_index + 1)

        call_one_level(instance_index=0)
        """
        ret_BGP = self.evalBGP_replacement(ctx, part.triples)
        return ret_BGP


# Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
def custom_eval_bgp(self, ctx, part):
    # part.name = "SelectQuery", "Project", "BGP"
    # print("customEval part.name=", part.name)
    if part.name == 'BGP':
        evaluator = EvalBGP(ctx, part)
        return evaluator.internal_eval_bgp()

    raise NotImplementedError()


class RdflibCustomEvalsReplaceEvalBgpTest(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_bgp'] = custom_eval_bgp

    def tearDown(self):
        if 'custom_eval_bgp' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_bgp']

    @unittest.skip("NOT YET")
    def test_replace_eval_bgp(self):
        pass



################################################################################

# Queries to test

# This returns the sibling processes (Same parent id) of the current process.
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
SELECT ?the_ppid
WHERE
{
  ?url_procA survol:Handle %d .
  ?url_procA survol:parent_pid ?the_ppid .
  ?url_procA rdf:type survol:CIM_Process .
  ?url_procB survol:Handle ?the_ppid .
  ?url_procB rdf:type survol:CIM_Process .
  ?url_procC survol:Handle %d .
  ?url_procC survol:parent_pid ?the_ppid .
  ?url_procC rdf:type survol:CIM_Process .
}
""" % (CurrentPid,CurrentPid)


# This should select the parent process id
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
SELECT ?the_ppid
WHERE
{ ?url_proc survol:Handle %d .
  ?url_proc survol:parent_pid ?the_ppid .
  ?url_proc rdf:type survol:CIM_Process .
}
"""

"""
SELECT *
WHERE
{
  ?url_dirA rdf:type survol:CIM_Directory .
  ?url_dirB survol:Name "C:/Program Files (x86)/Internet Explorer" .
  ?url_dirB survol:ParentDirectory ?url_dirA .
  ?url_dirB rdf:type survol:CIM_Directory .
}
"""

"""
SELECT *
WHERE
{
  ?url_dirA survol:Name "C:/Program Files (x86)" .
  ?url_dirA rdf:type survol:CIM_Directory .
  ?url_dirB survol:ParentDirectory ?url_dirA .
  ?url_dirB rdf:type survol:CIM_Directory .
}
"""

# This returns the parent process using a specific script.
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
SELECT *
WHERE
{ ?url_procA survol:Handle %d  .
  ?url_procA rdf:type survol:CIM_Process .
  ?url_procA rdfs:seeAlso "survol:CIM_Process/single_pidstree" .
  ?url_procA survol:ppid ?url_procB  .
  ?url_procB survol:runs ?filename  .
  ?url_procB rdf:type survol:CIM_Process .
}
"""

"""
SELECT *
WHERE
{ ?url_fileA survol:Name "C:/Windows"  .
  ?url_fileA rdf:type survol:CIM_Directory .
  ?url_fileA survol:CIM_DirectoryContainsFile ?url_fileB  .
  ?url_fileB rdfs:seeAlso "WMI" .
  ?url_fileB rdf:type survol:CIM_DataFile .
}
"""

"""
SELECT *
WHERE
{ ?url_proc survol:Handle %d  .
  ?url_proc rdf:type survol:CIM_Process .
  ?url_file rdfs:seeAlso "WMI" .
  ?url_file rdf:type survol:CIM_DataFile .
  ?url_file rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
  ?url_file survol:CIM_ProcessExecutable ?url_proc  .
}
"""


if __name__ == '__main__':
    unittest.main()

