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

# Not really used for the moment, but kept as a documentation.
class SurvolStore(rdflib.plugins.memory.IOMemory):
    def __init__(self, configuration=None, identifier=None):
        super(SurvolStore, self).__init__(configuration)

    def triples(self, t_triple, context=None):
        (t_subject, t_predicate, t_object) = t_triple
        print("triples vals=",t_subject, t_predicate, t_object)
        print("triples typs=",type(t_subject), type(t_predicate), type(t_object))

        """
        triples vals= None http://www.w3.org/1999/02/22-rdf-syntax-ns#type http://primhillcomputer.com/ontologies/CIM_Directory
        triples typs= <type 'NoneType'> <class 'rdflib.term.URIRef'> <class 'rdflib.term.URIRef'>
        """

        return super(SurvolStore, self).triples((t_subject, t_predicate, t_object), context)

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

################################################################################

def current_function():
    return sys._getframe(1).f_code.co_name

class BubbleInstance(object):
    def __init__(self, class_name, key_variable):
        self.m_variable = key_variable
        self.m_class_name = class_name
        self.m_associators = {}
        self.m_associated = {}
        self.m_properties = {}

    def __str__(self):
        def kw_to_str(property, value):
            property_str = str(property)[len(survol_url):]
            value_str = str(value)
            return "%s=%s" % (property_str, value_str)

        # print("ka=", self.m_known_attributes.items())
        kw = ".".join([ kw_to_str(property, value) for property, value in self.m_properties.items()])
        return "BubbleInstance:" + self.m_class_name + ":" + self.m_variable + ":" + kw

    def FetchAllVariables(self, graph, variables_context):
        raise NotImplementedError(current_function())


class Bubble_CIM_DataFile(BubbleInstance):
    def __init__(self, class_name, node):
        super(Bubble_CIM_DataFile, self).__init__(class_name, node)

    def FetchAllVariables(self, graph, variables_context):
        one_variables_set = {}

        if predicate_Name not in self.m_properties:
            return {}
        predicate_variable = self.m_properties[predicate_Name]
        if isinstance(predicate_variable, rdflib.term.Literal):
            node_file_path = predicate_variable
            file_path = str(predicate_variable)
        elif isinstance(predicate_variable, rdflib.term.Variable):
            if predicate_variable not in variables_context:
                return {}
            node_file_path = variables_context[predicate_variable]
            assert isinstance(node_file_path, rdflib.term.Literal)
            file_path = str(node_file_path)
        else:
            return {}

        url_as_str = "Machine:CIM_DataFile?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)

        one_variables_set[self.m_variable] = [node_uri_ref]
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_DataFile))

        one_variables_set[predicate_variable] = [node_file_path]
        graph.add((node_uri_ref, predicate_Name, node_file_path))

        assert associator_CIM_DirectoryContainsFile not in self.m_associators

        if associator_CIM_DirectoryContainsFile in self.m_associated:
            associator_instance = self.m_associated[associator_CIM_DirectoryContainsFile]
            assert isinstance(associator_instance, Bubble_CIM_Directory)
            assert isinstance(associator_instance.m_variable, rdflib.term.Variable)

            if associator_instance.m_variable in variables_context:
                print("ALREADY DEFINED ??")
            else:
                dir_file_path = os.path.dirname(file_path)
                dir_file_path_node = rdflib.term.Literal(dir_file_path)

                dir_node_str = "Machine:CIM_Directory?Name=" + dir_file_path
                associator_instance_url = rdflib.term.URIRef(dir_node_str)
                graph.add((associator_instance_url, rdflib.namespace.RDF.type, class_CIM_Directory))
                one_variables_set[associator_instance.m_variable] = associator_instance_url
                graph.add((associator_instance_url, associator_CIM_DirectoryContainsFile, node_uri_ref))

                if predicate_Name in associator_instance.m_properties:
                    dir_path_variable = associator_instance.m_properties[predicate_Name]
                    assert isinstance(dir_path_variable, rdflib.term.Variable)
                    one_variables_set[dir_path_variable] = [dir_file_path_node]

        return one_variables_set

class Bubble_CIM_Directory(BubbleInstance):
    def __init__(self, class_name, node):
        super(Bubble_CIM_Directory, self).__init__(class_name, node)

    def FetchAllVariables(self, graph, variables_context):
        one_variables_set = {}

        if predicate_Name not in self.m_properties:
            return {}
        predicate_variable = self.m_properties[predicate_Name]
        if isinstance(predicate_variable, rdflib.term.Literal):
            node_file_path = predicate_variable
            file_path = str(predicate_variable)
        elif isinstance(predicate_variable, rdflib.term.Variable):
            if predicate_variable not in variables_context:
                return {}
            node_file_path = variables_context[predicate_variable]
            assert isinstance(node_file_path, rdflib.term.Literal)
            file_path = str(node_file_path)
        else:
            return {}

        url_as_str = "Machine:CIM_Directory?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)

        one_variables_set[self.m_variable] = [node_uri_ref]
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_Directory))

        if node_file_path:
            one_variables_set[predicate_variable] = [node_file_path]
            graph.add((node_uri_ref, predicate_Name, node_file_path))


        if associator_CIM_DirectoryContainsFile in self.m_associated:
            associator_instance = self.m_associated[associator_CIM_DirectoryContainsFile]
            assert isinstance(associator_instance, Bubble_CIM_Directory)
            assert isinstance(associator_instance.m_variable, rdflib.term.Variable)

            if associator_instance.m_variable in variables_context:
                print("ALREADY DEFINED")
            else:
                dir_file_path = os.path.dirname(file_path)
                dir_file_path_node = rdflib.term.Literal(dir_file_path)

                dir_node_str = "Machine:CIM_Directiry?Name=" + dir_file_path
                associator_instance_url = rdflib.term.URIRef(dir_node_str)
                graph.add((associator_instance_url, rdflib.namespace.RDF.type, class_CIM_Directory))
                one_variables_set[associator_instance.m_variable] = associator_instance_url
                graph.add((associator_instance_url, associator_CIM_DirectoryContainsFile, node_uri_ref))

                if predicate_Name in associator_instance.m_properties:
                    dir_path_variable = associator_instance.m_properties[predicate_Name]
                    assert isinstance(dir_path_variable, rdflib.term.Variable)
                    one_variables_set[dir_path_variable] = [dir_file_path_node]

        if associator_CIM_DirectoryContainsFile in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_DirectoryContainsFile]
            assert isinstance(associated_instance, (Bubble_CIM_DataFile, Bubble_CIM_Directory))
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)

            sub_uri_ref_list = []

            for root_dir, dir_lists, files_list in os.walk(file_path):
                for one_file_name in files_list:
                    sub_path_name = os.path.join(root_dir, one_file_name)
                    sub_path_name_url = rdflib.term.Literal(sub_path_name)

                    def add_sub_node(sub_node_str, cim_class):
                        assert cim_class in (class_CIM_Directory, class_CIM_DataFile)
                        sub_node_uri_ref = rdflib.term.URIRef(sub_node_str)
                        graph.add((sub_node_uri_ref, rdflib.namespace.RDF.type, cim_class))
                        sub_uri_ref_list.append(sub_node_uri_ref)
                        graph.add((sub_node_uri_ref, predicate_Name, sub_path_name_url))
                        graph.add((node_uri_ref, associator_CIM_DirectoryContainsFile, sub_node_uri_ref))

                    if associated_instance.m_class_name == "CIM_Directory":
                        if os.path.isdir(sub_path_name):
                            sub_node_str = "Machine:CIM_Directory?Name=" + sub_path_name
                            add_sub_node(sub_node_str, class_CIM_Directory)
                    elif associated_instance.m_class_name == "CIM_DataFile":
                        if os.path.isfile(sub_path_name):
                            sub_node_str = "Machine:CIM_DataFile?Name=" + sub_path_name
                            add_sub_node(sub_node_str, class_CIM_DataFile)
                    else:
                        raise Exception("Invalid class name:"+associated_instance.m_class_name)
                break # Top-level only.

            one_variables_set[associated_instance.m_variable] = sub_uri_ref_list

        return one_variables_set



class Bubble_CIM_Process(BubbleInstance):
    def __init__(self, class_name, node):
        super(Bubble_CIM_DataFile, self).__init__(class_name, node)

def CreateBubbleInstance(class_name, the_subject):
    class_name_to_class = {
        "CIM_DataFile":Bubble_CIM_DataFile,
        "CIM_Directory": Bubble_CIM_Directory,
        "CIM_Process": Bubble_CIM_Process,
    }

    the_class = class_name_to_class[class_name]
    the_instance = the_class(class_name, the_subject)
    return the_instance

class_names_to_node = dict()

def part_triples_to_instances_dict_bubble(part):
    instances_dict = dict()
    print("Triples Bubble")
    for part_subject, part_predicate, part_object in part.triples:
        print("    ", part_subject, part_predicate, part_object)
        if part_predicate == rdflib.namespace.RDF.type:
            if isinstance(part_subject, rdflib.term.Variable):
                class_as_str = part_object.toPython()
                class_short = class_as_str[len(survol_url):]
                if class_as_str.startswith(survol_url):
                    class_names_to_node[class_short] = part_object
                    instances_dict[part_subject] = CreateBubbleInstance(class_short, part_subject)

    print("Created instances:", instances_dict.keys())

    for part_subject, part_predicate, part_object in part.triples:

        print("part_subject=", part_subject)
        current_instance = instances_dict.get(part_subject, None)
        print("current_instance=", current_instance)
        if not current_instance: continue
        assert isinstance(current_instance, BubbleInstance)
        if part_predicate == rdflib.namespace.RDF.type: continue

        if part_predicate == rdflib.namespace.RDFS.seeAlso: continue

        print("part_object=", part_object)
        associator_instance = instances_dict.get(part_object, None)
        if associator_instance:
            assert isinstance(associator_instance, BubbleInstance)
            current_instance.m_associators[part_predicate] = associator_instance
            associator_instance.m_associated[part_predicate] = current_instance
        else:
            current_instance.m_properties[part_predicate] = part_object

    return instances_dict

def find_known_instance(graph, instances_dict, variables_context):
    print("find_known_instance from:", instances_dict.keys())
    for key_instance, one_instance in instances_dict.items():
        returned_variables = one_instance.FetchAllVariables(graph, variables_context)
        if returned_variables:
            return key_instance, returned_variables

    return None, None

# The input is a set of {variable: list-of-values.
# It returns a set of {variable: value}
def product_variables_lists(returned_variables, iter_keys = None):
    try:
        if not iter_keys:
            iter_keys = iter(returned_variables.items())
        key, values_list = next(iter_keys)
        for one_dict in product_variables_lists(returned_variables, iter_keys):
            for one_value in values_list:
                new_dict = one_dict.copy()
                new_dict[key] = one_value
                yield new_dict
    except StopIteration:
        yield {}

# Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
def custom_eval_bubble(ctx, part):
    # part.name = "SelectQuery", "Project", "BGP"
    if part.name == 'BGP':
        print("ctx:", ctx)
        print("dir(ctx):", dir(ctx))
        print("part:", dir(part))
        print("Triples:")
        for one_triple in part.triples:
            print("   *** ", one_triple)
            ss,pp,oo = one_triple
            print("   $$$ ", ss,pp,oo)

        add_ontology(ctx.graph)

        print("Instances:")
        instances_dict = part_triples_to_instances_dict_bubble(part)
        for instance_key, one_instance in instances_dict.items():
            print("    Key=", instance_key)
            print("    Instance=", one_instance)

        explored_instances = []
        # This is a dictionary of variables.
        variables_context = {}

        def recursive_instantiation():
            print("recursive_instantiation:", instances_dict.keys())

            # This returns the first instance which is completely kown, i.e. its parameters
            # are iterals, or variables whose values are known in the current context.
            key_best_instance, returned_variables = find_known_instance(ctx.graph, instances_dict, variables_context)
            print("key_best_instance=", key_best_instance)
            print("returned_variables=", returned_variables)

            if not key_best_instance:
                return

            best_instance = instances_dict[key_best_instance]
            del instances_dict[key_best_instance]
            explored_instances.append(key_best_instance)
            for one_subset in product_variables_lists(returned_variables):
                print("one_subset=", one_subset)
                variables_context.update(one_subset)
                print("variables_context=", variables_context)
                print("part.graph=", ctx.graph)
                recursive_instantiation()

        recursive_instantiation()

        # <type 'generator'>
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP

    raise NotImplementedError()


class RdflibCustomEvalsBubbleTest(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_bubble'] = custom_eval_bubble

    def tearDown(self):
        if 'custom_eval_bubble' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_bubble']

    @staticmethod
    def one_return_tst(return_variables):
        # https://docs.python.org/3/library/itertools.html#itertools.combinations
        # itertools.product
        results = product_variables_lists(return_variables)
        print("return_variables=", return_variables)
        for one_resu in results:
            print("one_resu=", one_resu)

    def test_prod_variables(self):
        RdflibCustomEvalsBubbleTest.one_return_tst({ 'a':['a1'],'b':['b1'],'c':['c1'], })
        RdflibCustomEvalsBubbleTest.one_return_tst({ 'a':['a1'],'b':['b1','b2'],'c':['c1'], })

    #@unittest.skip("Not DONE")
    def test_query_bubble_parent(self):
        rdflib_graph = CreateGraph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_directory survol:Name ?directory_name .
                ?url_datafile survol:Name "%s" .
            }
        """ % (survol_namespace, tmp_pathname)

        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    #@unittest.skip("Not DONE")
    def test_query_bubble_children(self):
        rdflib_graph = CreateGraph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_datafile survol:Name ?datafile_name .
                ?url_directory survol:Name "%s" .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)


    def test_query_bubble_grandparent(self):
        rdflib_graph = CreateGraph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?grandparent_name WHERE {
                ?url_grandparent a survol:CIM_Directory .
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_grandparent survol:CIM_DirectoryContainsFile ?url_directory .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_grandparent survol:Name ?grandparent_name .
                ?url_datafile survol:Name "%s" .
            }
        """ % (survol_namespace, tmp_pathname)

        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)

    def test_query_bubble_grandchildren(self):
        rdflib_graph = CreateGraph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name WHERE {
                ?url_grandparent a survol:CIM_Directory .
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_grandparent survol:CIM_DirectoryContainsFile ?url_directory .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_grandparent survol:Name "%s" .
                ?url_datafile survol:Name ?datafile_name .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))
        print("Result=", query_result)



if __name__ == '__main__':
    unittest.main()

