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
        # print("triples vals=",t_subject, t_predicate, t_object)
        # print("triples typs=",type(t_subject), type(t_predicate), type(t_object))

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

# This is not part of the ontology but allows to return several processes,
# based on their parent process id.
predicate_ParentProcessId = rdflib.term.URIRef(survol_url + "ParentProcessId")

associator_CIM_DirectoryContainsFile = rdflib.term.URIRef(survol_url + "CIM_DirectoryContainsFile")
associator_CIM_ProcessExecutable = rdflib.term.URIRef(survol_url + "CIM_ProcessExecutable")
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
    graph.add((predicate_Handle, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.integer))

    graph.add((predicate_ParentProcessId, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.domain, class_CIM_Process))
    graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((predicate_ParentProcessId, rdflib.namespace.RDFS.label, rdflib.Literal("ParentProcessId")))

    graph.add((predicate_Name, rdflib.namespace.RDF.type, rdflib.namespace.RDF.Property))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_Directory))
    graph.add((predicate_Name, rdflib.namespace.RDFS.domain, class_CIM_DataFile))
    graph.add((predicate_Name, rdflib.namespace.RDFS.range, rdflib.namespace.XSD.string))
    graph.add((predicate_Name, rdflib.namespace.RDFS.label, rdflib.Literal("Name")))

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

################################################################################

# Queries to test

# This returns the sibling processes (Same parent id) of the current process.
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
SELECT ?the_ppid
WHERE
{
  ?url_procA survol:Handle %d .
  ?url_procA survol:ParentProcessId ?the_ppid .
  ?url_procA rdf:type survol:CIM_Process .
  ?url_procB survol:Handle ?the_ppid .
  ?url_procB rdf:type survol:CIM_Process .
  ?url_procC survol:Handle %d .
  ?url_procC survol:ParentProcessId ?the_ppid .
  ?url_procC rdf:type survol:CIM_Process .
}
""" % (CurrentPid,CurrentPid)


"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
SELECT ?pid_sibling
WHERE
{
  ?url_proc_parent rdf:type survol:CIM_Process .
  ?url_proc_mine rdf:type survol:CIM_Process .
  ?url_proc_sibling rdf:type survol:CIM_Process .
  ?url_proc_mine survol:ParentProcessId ?ppid .
  ?url_proc_sibling survol:ParentProcessId ?ppid .
  ?url_proc_mine survol:Handle %d .
  ?url_proc_parent survol:Handle ?ppid .
  ?url_proc_sibling survol:Handle ?pid_sibling .
}
""" % (os.getpid())

# This returns the parent process using a specific script.
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?filename
WHERE
{
  ?url_proc_parent survol:Handle ?pid_proc_parent  .
  ?url_process survol:Handle %d  .
  ?url_process rdf:type survol:CIM_Process .
  ?url_process survol:ParentProcessId ?pid_proc_parent  .
  ?url_proc_parent survol:CIM_ProcessExecutable ?filename  .
  ?url_proc_parent rdf:type survol:CIM_Process .
}
"""

"""
SELECT ?directory_name
WHERE
  ?url_proc rdf:type survol:CIM_Process .
  ?url_file rdf:type survol:CIM_DataFile .
  ?url_directory rdf:type survol:CIM_Directory .
  ?url_directory survol:Handle ?directory_name .
{ ?url_proc survol:Handle %d  .
  ?url_proc survol:CIM_ProcessExecutable ?url_file  .
  ?url_directory survol:CIM_DirectoryContainsFile ?url_file  .
}
"""

# Comment va-t-on passer du procid vers le process ?

# Directory of the executable run by the parent of the current process.
"""
SELECT ?directory_name
WHERE
  ?url_directory rdf:type survol:CIM_Directory .
  ?url_proc rdf:type survol:CIM_Process .
  ?url_parent_proc rdf:type survol:CIM_Process .
  ?url_file rdf:type survol:CIM_DataFile .
  ?url_proc survol:Handle %d .
  ?url_parent_proc survol:Handle ?parent_proc_id .
  ?url_proc survol:ParentProcessId ?parent_proc_id  .
  ?url_directory survol:Name ?directory_name .
  ?url_parent_proc survol:CIM_ProcessExecutable ?url_file  .
  ?url_directory survol:CIM_DirectoryContainsFile ?url_file  .
}
""" % (os.getpid())

################################################################################

def current_function():
    return sys._getframe(1).f_code.co_name

class Sparql_CIM_Object(object):
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
        return "Sparql_CIM_Object:" + self.m_class_name + ":" + self.m_variable + ":" + kw

    def FetchAllVariables(self, graph, variables_context):
        print("FetchAllVariables not implemented")
        raise NotImplementedError(current_function())

    def CalculateVariablesNumber(self):
        self.m_number_variables = 0
        self.m_number_literals = 0
        for one_dict in [self.m_associators, self.m_associated, self.m_properties]:
            for key, value in one_dict.items():
                if isinstance(value, rdflib.term.Variable):
                    self.m_number_variables += 1
                elif isinstance(value, rdflib.term.Literal):
                    self.m_number_literals += 1

    def GetNodeValue(self, predicate_node, variables_context):
        predicate_variable = self.m_properties[predicate_node]
        if isinstance(predicate_variable, rdflib.term.Literal):
            node_value = predicate_variable
        elif isinstance(predicate_variable, rdflib.term.Variable):
            if predicate_variable not in variables_context:
                print("GetNodeValue QUIT:", predicate_variable, "not in", variables_context.keys())
                return None
            node_value = variables_context[predicate_variable]
            print("predicate_variable=", predicate_variable, "node_value=", node_value)
            assert isinstance(node_value, rdflib.term.Literal)
        return node_value


class Sparql_CIM_DataFile(Sparql_CIM_Object):
    def __init__(self, class_name, node):
        super(Sparql_CIM_DataFile, self).__init__(class_name, node)

    def FetchFromProperties(self, variables_context):
        print("Sparql_CIM_DataFile.FetchFromProperties")
        if predicate_Name in self.m_properties:
            return self.GetNodeValue(predicate_Name, variables_context)
        else:
            print("Sparql_CIM_DataFile QUIT: No Name")
            return None


    def FetchFromDirectory(self, variables_context, file_path, graph, returned_variables, node_uri_ref):
        print("Sparql_CIM_DataFile.FetchFromDirectory file_path=", file_path)
        if associator_CIM_DirectoryContainsFile in self.m_associated:
            associator_instance = self.m_associated[associator_CIM_DirectoryContainsFile]
            assert isinstance(associator_instance, Sparql_CIM_Directory)
            assert isinstance(associator_instance.m_variable, rdflib.term.Variable)

            if associator_instance.m_variable in variables_context:
                print("ALREADY DEFINED ??", associator_instance.m_variable)
                return

            dir_file_path = os.path.dirname(file_path)
            dir_file_path_node = rdflib.term.Literal(dir_file_path)

            dir_node_str = "Machine:CIM_Directory?Name=" + dir_file_path
            associator_instance_url = rdflib.term.URIRef(dir_node_str)
            graph.add((associator_instance_url, rdflib.namespace.RDF.type, class_CIM_Directory))
            graph.add((associator_instance_url, associator_CIM_DirectoryContainsFile, node_uri_ref))

            if predicate_Name in associator_instance.m_properties:
                dir_path_variable = associator_instance.m_properties[predicate_Name]
                assert isinstance(dir_path_variable, rdflib.term.Variable)
            else:
                # This property must be created, to make the directory usable,
                # for example to get its other properties.
                # Generally speaking, this must be done for all properties of the ontology.
                variable_name = str(associator_instance.m_variable) + "_dummy_name"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associator_instance.m_properties[predicate_Name] = dir_path_variable

            if isinstance(dir_path_variable, rdflib.term.Variable):
                returned_variables[(associator_instance,dir_path_variable)] = [(associator_instance_url, dir_file_path_node)]
            else:
                returned_variables[associator_instance.m_variable] = [associator_instance_url]
            graph.add((associator_instance_url, predicate_Name, dir_file_path_node))

    def FetchAllVariables(self, graph, variables_context):
        node_file_path = self.FetchFromProperties(variables_context)
        if not node_file_path:
            return {}
        file_path = str(node_file_path)
        returned_variables = {}

        url_as_str = "Machine:CIM_DataFile?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_DataFile))

        returned_variables[self.m_variable] = [node_uri_ref]

        # No need to add node_file_path in the results because,
        # if it is a Variable, it is already in the context.
        assert isinstance(self.m_variable, rdflib.term.Variable)
        assert node_file_path
        graph.add((node_uri_ref, predicate_Name, node_file_path))

        assert associator_CIM_DirectoryContainsFile not in self.m_associators

        self.FetchFromDirectory(variables_context, file_path, graph, returned_variables, node_uri_ref)

        # TODO: If there are no properties and no directory, this should return ALL FILES OF THE FILE SYSTEM.

        return returned_variables

class Sparql_CIM_Directory(Sparql_CIM_DataFile):
    def __init__(self, class_name, node):
        super(Sparql_CIM_Directory, self).__init__(class_name, node)

    def FetchAllVariables(self, graph, variables_context):
        node_file_path = self.FetchFromProperties(variables_context)
        if not node_file_path:
            return {}
        file_path = str(node_file_path)
        returned_variables = {}

        url_as_str = "Machine:CIM_Directory?Name=" + file_path
        node_uri_ref = rdflib.term.URIRef(url_as_str)

        assert isinstance(self.m_variable, rdflib.term.Variable)
        returned_variables[self.m_variable] = [node_uri_ref]
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_CIM_Directory))

        # No need to add node_file_path in the results=:
        # This Variable is already in the context.
        assert node_file_path
        graph.add((node_uri_ref, predicate_Name, node_file_path))

        self.FetchFromDirectory(variables_context, file_path, graph, returned_variables, node_uri_ref)

        if associator_CIM_DirectoryContainsFile in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_DirectoryContainsFile]
            assert isinstance(associated_instance, (Sparql_CIM_DataFile, Sparql_CIM_Directory))
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)

            return_values_list = []

            if predicate_Name in associated_instance.m_properties:
                dir_path_variable = associated_instance.m_properties[predicate_Name]
                print("dir_path_variable=", dir_path_variable, type(dir_path_variable))
                print("Sparql_CIM_Directory.FetchAllVariables dir_path_variable=", dir_path_variable)
            else:
                # This creates a temporary variable to store the name because
                # it might be necessary to identify this associated instance.
                # This is needed for all properties of the ontology.
                variable_name = str(associated_instance.m_variable) + "_dummy_subname"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associated_instance.m_properties[predicate_Name] = dir_path_variable
                print("Sparql_CIM_Directory.FetchAllVariables Created dummy variable:", variable_name)

            def add_sub_node(sub_node_str, cim_class, sub_path_name):
                print("Sparql_CIM_Directory.FetchAllVariables add_sub_node ", sub_node_str, "sub_path_name=", sub_path_name)
                assert cim_class in (class_CIM_Directory, class_CIM_DataFile)
                sub_node_uri_ref = rdflib.term.URIRef(sub_node_str)
                graph.add((sub_node_uri_ref, rdflib.namespace.RDF.type, cim_class))
                #sub_uri_ref_list.append(sub_node_uri_ref)
                sub_path_name_url = rdflib.term.Literal(sub_path_name)
                graph.add((sub_node_uri_ref, predicate_Name, sub_path_name_url))
                graph.add((node_uri_ref, associator_CIM_DirectoryContainsFile, sub_node_uri_ref))

                if isinstance(dir_path_variable, rdflib.term.Variable):
                    #sub_path_name_url_list.append(sub_path_name_url)
                    return_values_list.append((sub_node_uri_ref, sub_path_name_url))
                    # returned_variables[dir_path_variable] = [sub_path_name_url]
                else:
                    return_values_list.append(sub_node_uri_ref)
                    assert isinstance(dir_path_variable, rdflib.term.Literal)
                    print("Associated object Name is literal:", dir_path_variable)

            file_path = file_path.replace("\\", "/")
            print("Sparql_CIM_Directory.FetchAllVariables file_path=", file_path)
            for root_dir, dir_lists, files_list in os.walk(file_path):
                if associated_instance.m_class_name == "CIM_Directory":
                    for one_file_name in dir_lists:
                        sub_path_name = os.path.join(root_dir, one_file_name)
                        assert os.path.isdir(sub_path_name)
                        sub_node_str = "Machine:CIM_Directory?Name=" + sub_path_name
                        add_sub_node(sub_node_str, class_CIM_Directory, sub_path_name)
                elif associated_instance.m_class_name == "CIM_DataFile":
                    for one_file_name in files_list:
                        sub_path_name = os.path.join(root_dir, one_file_name)
                        print("sub_path_name=", sub_path_name)
                        assert os.path.isfile(sub_path_name)
                        sub_node_str = "Machine:CIM_DataFile?Name=" + sub_path_name
                        add_sub_node(sub_node_str, class_CIM_DataFile, sub_path_name)
                else:
                    raise Exception("Cannot happen")
                # Loop on first level only.
                break

            print("Sparql_CIM_Directory.FetchAllreturn_values_list", return_values_list)
            if isinstance(dir_path_variable, rdflib.term.Variable):
                print("Sparql_CIM_Directory.FetchAllVariables Returning variables pair:", associated_instance.m_variable, dir_path_variable)
                returned_variables[(associated_instance.m_variable, dir_path_variable)] = return_values_list #[(sub_uri_ref_list, sub_path_name_url_list)]
            else:
                print("Sparql_CIM_Directory.FetchAllVariables Returning variable:", associated_instance.m_variable)
                returned_variables[associated_instance.m_variable] = return_values_list # [sub_uri_ref_list]

            # returned_variables[associated_instance.m_variable] = sub_uri_ref_list
            print("Sparql_CIM_Directory.FetchAllVariables FetchAllVariables returned_variables=", returned_variables)

        # TODO: If there are no properties and no directory and no sub-files or sub-directories,
        # TODO: this should return ALL DIRECTORIES OF THE FILE SYSTEM.

        return returned_variables



class Sparql_CIM_Process(Sparql_CIM_Object):
    def __init__(self, class_name, node):
        super(Sparql_CIM_Process, self).__init__(class_name, node)

    # Several properties can be used to return one or several objects.
    # TODO: We could use several properties at one: It is difficult to generalise.
    class PropertyDefinition:
        class property_definition_Handle:
            s_property_node = predicate_Handle

            def IfLiteralOrDefinedVariable(self, node_value):
                process_id = int(str(node_value))
                parent_process_pid =  psutil.Process(process_id).ppid()
                dict_process = {predicate_Handle: node_value,
                                predicate_ParentProcessId: rdflib.term.Literal(parent_process_pid)}
                return [dict_process]

        class property_definition_ParentProcessId:
            s_property_node = predicate_ParentProcessId

            def IfLiteralOrDefinedVariable(self, node_value):
                result_list=[]
                ppid = int(str(node_value))
                for child_process in psutil.Process(ppid).children(recursive=False):
                    dict_process={predicate_Handle:rdflib.term.Literal(child_process.pid),
                                   predicate_ParentProcessId:node_value}
                    result_list.append(dict_process)
                return result_list

        g_properties = [
            property_definition_Handle(),
            property_definition_ParentProcessId()
        ]

    # If no property is usable, this returns all objects.
    # This can work only for some classes, if there are not too many objects.
    def GetAllObjects(self):
        print("GetAllObjects")
        result_list = []
        for proc in psutil.process_iter():
            dict_process = {predicate_Handle: rdflib.term.Literal(proc.pid),
                            predicate_ParentProcessId: rdflib.term.Literal(proc.ppid())}
            result_list.append(dict_process)
        return result_list

    def GetListOfOntologyProperties(self, variables_context):
        print("GetListOfOntologyProperties")
        for one_property in self.PropertyDefinition.g_properties:
            print("    GetListOfOntologyProperties one_property=", one_property.s_property_node)
            if one_property.s_property_node in self.m_properties:
                node_value = self.GetNodeValue(one_property.s_property_node, variables_context)
                if node_value:
                    assert isinstance(node_value, rdflib.term.Literal)
                    url_nodes_list = one_property.IfLiteralOrDefinedVariable(node_value)
                    return url_nodes_list
        print("GetListOfOntologyProperties leaving: Cannot find anything.")
        return None

    def CreateURIRef(self, graph, class_name, class_node, dict_predicates_to_values):
        url_as_str = "Machine:" + class_name
        delimiter = "?"
        for node_predicate, node_value in dict_predicates_to_values.items():
            predicate_name = str(node_predicate)[len(survol_url):]
            str_value = str(node_value)
            url_as_str += delimiter + "%s=%s" % (predicate_name, str_value)
            delimiter = "."
        print("CreateURIRef url_as_str=", url_as_str)
        node_uri_ref = rdflib.term.URIRef(url_as_str)
        graph.add((node_uri_ref, rdflib.namespace.RDF.type, class_node))

        for node_predicate, node_value in dict_predicates_to_values.items():
            assert isinstance(node_value, rdflib.term.Literal)
            graph.add((node_uri_ref, node_predicate, node_value))
        return node_uri_ref

    # Given the process id, it creates the file representing the executable being run.
    def DefineExecutableFromProcess(self, variables_context, process_id, graph, returned_variables, node_uri_ref):
        print("Sparql_CIM_Process.DefineExecutableFromProcess process_id=", process_id)
        if associator_CIM_ProcessExecutable in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
            assert isinstance(associated_instance, Sparql_CIM_DataFile)
            assert isinstance(associated_instance.m_variable, rdflib.term.Variable)
            assert isinstance(process_id, int)

            # This calculates the variable which defines the executable node.
            assert associated_instance.m_variable not in variables_context

            # TODO: This could also explore DLLs, not only the main executable.
            executable_path = psutil.Process(process_id).exe()
            executable_path_node = rdflib.term.Literal(executable_path)

            associated_instance_url = self.CreateURIRef(graph, "CIM_DataFile", class_CIM_DataFile,
                         {predicate_Name: executable_path_node})

            graph.add((node_uri_ref, associator_CIM_ProcessExecutable, associated_instance_url))

            if predicate_Name in associated_instance.m_properties:
                dir_path_variable = associated_instance.m_properties[predicate_Name]
                assert isinstance(dir_path_variable, rdflib.term.Variable)
            else:
                # This property must be created, to make the directory usable,
                # for example to get its other properties.
                # Generally speaking, this must be done for all properties of the ontology.
                variable_name = str(associated_instance.m_variable) + "_dummy_name"
                dir_path_variable = rdflib.term.Variable(variable_name)
                associated_instance.m_properties[predicate_Name] = dir_path_variable

            if isinstance(dir_path_variable, rdflib.term.Variable):
                assert (associated_instance, dir_path_variable) not in returned_variables
                returned_variables[(associated_instance, dir_path_variable)] = [
                    (associated_instance_url, executable_path_node)]
            else:
                assert associated_instance.m_variable not in returned_variables
                returned_variables[associated_instance.m_variable] = [associated_instance_url]
            graph.add((associated_instance_url, predicate_Name, executable_path_node))

    # Given a file name, it returns all processes executing it.
    def GetProcessesFromExecutable(self, graph, variables_context):
        print("Sparql_CIM_Process.GetProcessesFromExecutable")
        associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
        assert isinstance(associated_instance, Sparql_CIM_DataFile)
        assert isinstance(associated_instance.m_variable, rdflib.term.Variable)
        assert associated_instance.m_variable in variables_context

        print("Sparql_CIM_Process.GetProcessesFromExecutable variables_context=", variables_context)
        print("associated_instance.m_variable=", associated_instance.m_variable)
        executable_node = associated_instance.GetNodeValue(predicate_Name, variables_context)
        assert isinstance(executable_node, rdflib.term.Literal)
        executable_path = str(executable_node)
        # Because of backslashes transformed into slashes, which is necessary because of Sparql.
        executable_path = os.path.normpath(executable_path)
        print("executable_path=", executable_path)

        process_urls_list = []
        for one_process in psutil.process_iter():
            try:
                process_executable = one_process.exe()
            except psutil.AccessDenied as exc:
                print("GetProcessesFromExecutable Caught:", exc)
                continue
            # print("process_executable=", process_executable, "executable_path=", executable_path)
            if executable_path == process_executable:
                process_url = self.CreateURIRef(
                    graph, "CIM_Process", class_CIM_Process,
                    {predicate_Handle: rdflib.term.Literal(one_process.pid)})
                print("Adding process ", process_url)
                graph.add((process_url, associator_CIM_ProcessExecutable, executable_node))
                process_urls_list.append(process_url)
        return process_urls_list
        print("GetProcessesFromExecutable process_urls_list=", process_urls_list)

    def FetchAllVariables(self, graph, variables_context):
        print("Sparql_CIM_Process.FetchAllVariables variables_context=", variables_context)
        url_nodes_list = self.GetListOfOntologyProperties(variables_context)

        returned_variables = {}

        if isinstance(url_nodes_list, list) and len(url_nodes_list) == 0:
            print("FetchAllVariables No such process with self.m_properties:", self.m_properties)
            # No such process.
            return returned_variables

        if associator_CIM_ProcessExecutable in self.m_associators:
            associated_instance = self.m_associators[associator_CIM_ProcessExecutable]
            if associated_instance.m_variable in variables_context:
                if url_nodes_list is not None:
                    raise Exception("BUG: Contradiction with non-empty processe list")
                node_uri_refs_list = self.GetProcessesFromExecutable(graph, variables_context)
                returned_variables[self.m_variable] = node_uri_refs_list
                return returned_variables

        if not url_nodes_list:
            # Get all objects by default.
            url_nodes_list = self.GetAllObjects()

        node_uri_refs_list = []

        for properties_dict in url_nodes_list:
            print("Before CreateURIRef properties_dict=", properties_dict)
            node_uri_ref = self.CreateURIRef(graph, "CIM_Process", class_CIM_Process, properties_dict)
            node_uri_refs_list.append(node_uri_ref)

            process_id = int(properties_dict[predicate_Handle])
            self.DefineExecutableFromProcess(variables_context, process_id, graph, returned_variables, node_uri_ref)

        assert isinstance(self.m_variable, rdflib.term.Variable)
        assert self.m_variable not in returned_variables
        returned_variables[self.m_variable] = node_uri_refs_list
        return returned_variables

def CreateSparql_CIM_Object(class_name, the_subject):
    class_name_to_class = {
        "CIM_DataFile":Sparql_CIM_DataFile,
        "CIM_Directory": Sparql_CIM_Directory,
        "CIM_Process": Sparql_CIM_Process,
    }

    the_class = class_name_to_class[class_name]
    the_instance = the_class(class_name, the_subject)
    return the_instance

################################################################################

# This takes the list of triples extracted from the Sparql query,
# and returns a list of instances of CIM classes, each of them
# containing the triples using its instances. The association is
# done based on the variable representing the instance.
# There might be several instances of the same class.
def part_triples_to_instances_dict_function(part):
    instances_dict = dict()
    #print("Triples Bubble")
    for part_subject, part_predicate, part_object in part.triples:
        #print("    ", part_subject, part_predicate, part_object)
        if part_predicate == rdflib.namespace.RDF.type:
            if isinstance(part_subject, rdflib.term.Variable):
                class_as_str = part_object.toPython()
                class_short = class_as_str[len(survol_url):]
                if class_as_str.startswith(survol_url):
                    instances_dict[part_subject] = CreateSparql_CIM_Object(class_short, part_subject)

    print("Created instances:", instances_dict.keys())

    for part_subject, part_predicate, part_object in part.triples:
        current_instance = instances_dict.get(part_subject, None)
        if not current_instance: continue
        assert isinstance(current_instance, Sparql_CIM_Object)
        if part_predicate == rdflib.namespace.RDF.type: continue

        if part_predicate == rdflib.namespace.RDFS.seeAlso: continue

        associator_instance = instances_dict.get(part_object, None)
        if associator_instance:
            assert isinstance(associator_instance, Sparql_CIM_Object)
            current_instance.m_associators[part_predicate] = associator_instance
            associator_instance.m_associated[part_predicate] = current_instance
        else:
            assert isinstance(part_object, (rdflib.term.Literal, rdflib.term.Variable))
            current_instance.m_properties[part_predicate] = part_object

    return instances_dict

# The input is a set of {variable: list-of-values.
# It returns a set of {variable: value}
def product_variables_lists(returned_variables, iter_keys = None):
    try:
        if not iter_keys:
            iter_keys = iter(returned_variables.items())
        key, values_list = next(iter_keys)
        assert isinstance(values_list, list)

        for one_dict in product_variables_lists(returned_variables, iter_keys):
            for one_value in values_list:
                new_dict = one_dict.copy()
                if isinstance(key, tuple):
                    # Maybe, several correlated variables.
                    assert isinstance(one_value, tuple) and len(key) == len(one_value)
                    sub_dict = dict(zip(key, one_value))
                    new_dict.update(sub_dict)
                else:
                    new_dict[key] = one_value
                yield new_dict
    except StopIteration:
        yield {}

# An instance which is completely known and can be used as a starting point.
def findable_instance_key(instances_dict):
    print("findable_instance_key")
    for instance_key, one_instance in instances_dict.items():
        one_instance.CalculateVariablesNumber()
        print("    Key=", instance_key, "Instance=", one_instance)
        # Maybe we could return the instance with the greatest number of
        # literals ? Or the one whose implied instances are the fastest to find.
        # if one_instance.m_number_variables == 0 and one_instance.m_number_literals > 0:

        # We want to be able to retrieve at least one object, and as fast as possible.
        # This should check if wthe properties of the ontology are defined,
        # this is very important for WMI otherwise the performance can be awful.
        # On the other hand, in the general case, any property is enough, maybe none of them.
        # Realistically, in this examples, the ontologies properties are required.
        if one_instance.m_number_literals > 0:
            return instance_key

    # Could not find an instance with enough information.
    # The only possibility is to list all object. So, return the first instance.
    for instance_key, one_instance in instances_dict.items():
        return instance_key

# Exploration of the graph, starting by the ones which can be calculated without inference.
def visit_all_nodes(instances_dict):
    # Find a string point to walk the entire graph.
    start_instance_key = findable_instance_key(instances_dict)
    start_instance = instances_dict[start_instance_key]

    for instance_key, one_instance in instances_dict.items():
        one_instance.m_visited = False

    visited_instances = []

    def instance_recursive_visit(one_instance):
        assert isinstance(one_instance, Sparql_CIM_Object)
        one_instance.m_visited = True
        visited_instances.append(one_instance)
        for sub_instance in one_instance.m_associators.values():
            if not sub_instance.m_visited:
                instance_recursive_visit(sub_instance)
        for sub_instance in one_instance.m_associated.values():
            if not sub_instance.m_visited:
                instance_recursive_visit(sub_instance)

        # The input instance is known if and only if it is possible
        # to give a value to all the variables it may contain.
        # If not all of them are known, too many values might be produced,
        # the extreme case being to return all possible instances of a class.
        # TODO: The right thing is to walk the graph is incrementally aggregate
        # TODO: the list of known variables, choosing as next node, the ones
        # TODO: using these variables and no other, preferably.
        # FIXME: If some nodes are not viisted, just append them.

    instance_recursive_visit(start_instance)

    for instance_key, one_instance in instances_dict.items():
        if not one_instance.m_visited:
            visited_instances.append(one_instance)

    return visited_instances


# Inspired from https://rdflib.readthedocs.io/en/stable/_modules/examples/custom_eval.html
def custom_eval_function(ctx, part):
    # part.name = "SelectQuery", "Project", "BGP"
    if part.name == 'BGP':
        add_ontology(ctx.graph)

        print("Instances:")
        instances_dict = part_triples_to_instances_dict_function(part)
        print("Instance before sort", len(instances_dict))
        for instance_key, one_instance in instances_dict.items():
            print("    Key=", instance_key, "Instance=", one_instance)

        visited_nodes = visit_all_nodes(instances_dict)
        assert len(instances_dict) == len(visited_nodes)
        print("GRAPH VISIT:", len(visited_nodes))
        for one_instance in visited_nodes:
            print("    Instance=", one_instance)


        # This is a dictionary of variables.
        variables_context = {}

        def recursive_instantiation(instance_index):
            if instance_index == len(visited_nodes):
                print("recursive_instantiation End of recursive loop")
                return
            margin = " " + str(instance_index) + "    " * (instance_index + 1)
            print("recursive_instantiation: ix=", instance_index,
                  "visited nodes=", [nod.m_variable for nod in visited_nodes])

            # This returns the first instance which is completely kown, i.e. its parameters
            # are iterals, or variables whose values are known in the current context.
            one_instance = visited_nodes[instance_index]
            print(margin + "one_instance=", one_instance)
            returned_variables = one_instance.FetchAllVariables(ctx.graph, variables_context)

            print(margin + "returned_variables=", returned_variables)

            for one_subset in product_variables_lists(returned_variables):
                variables_context.update(one_subset)
                recursive_instantiation(instance_index+1)

        recursive_instantiation(0)

        print("Graph after recursive_instantiation")
        for s,p,o in ctx.graph:
            print("   ", s, p, o)

        # <type 'generator'>
        ret_BGP = rdflib.plugins.sparql.evaluate.evalBGP(ctx, part.triples)
        return ret_BGP

    raise NotImplementedError()


class Rdflib_CUSTOM_EVALS_Test(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function'] = custom_eval_function

    def tearDown(self):
        if 'custom_eval_function' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function']

    @staticmethod
    def one_return_tst(return_variables):
        # https://docs.python.org/3/library/itertools.html#itertools.combinations
        # itertools.product
        results = product_variables_lists(return_variables)
        print("return_variables=", return_variables)
        for one_resu in results:
            print("one_resu=", one_resu)

    @unittest.skip("Should use variables")
    def test_prod_variables(self):
        Rdflib_CUSTOM_EVALS_Test.one_return_tst({ 'a':['a1'],'b':['b1'],'c':['c1'], })
        Rdflib_CUSTOM_EVALS_Test.one_return_tst({ 'a':['a1'],'b':['b1','b2'],'c':['c1'], })

    #@unittest.skip("Not DONE")
    def test_sparql_parent(self):
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
        self.assertTrue( str(query_result[0][0]) == TempDirPath)
        print("Result=", query_result)

    def test_sparql_children_files(self):
        rdflib_graph = CreateGraph()

        # C:/Windows/temp\\survol_temp_file_12532.tmp'
        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

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
        self.assertTrue( tmp_pathname in [str(node[0]).replace("\\", "/") for node in query_result])

    def test_sparql_grandparent(self):
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
        self.assertTrue( str(query_result[0][0]) == os.path.dirname(TempDirPath))

    def test_sparql_grandchildren_files(self):
        rdflib_graph = CreateGraph()

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

        expected_files = set()
        for root_dir, dir_lists, files_list in os.walk(TempDirPath):
            if os.path.dirname(root_dir) == TempDirPath:
                for one_file_name in files_list:
                    sub_path_name = os.path.join(root_dir, one_file_name)
                    expected_files.add(sub_path_name.replace("\\","/"))

        actual_files = set([str(one_path_url[0]).replace("\\","/") for one_path_url in query_result])
        print("actual_files=", actual_files)
        print("expected_files=", expected_files)
        self.assertTrue(actual_files == expected_files)

    def test_sparql_grandchildren_directories(self):
        rdflib_graph = CreateGraph()

        tmp_pathname = create_temp_file()

        # Sparql does not accept backslashes.
        tmp_pathname = tmp_pathname.replace("\\", "/")

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_grandparent a survol:CIM_Directory .
                ?url_directory a survol:CIM_Directory .
                ?url_subdirectory a survol:CIM_Directory .
                ?url_grandparent survol:CIM_DirectoryContainsFile ?url_directory .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_subdirectory .
                ?url_grandparent survol:Name "%s" .
                ?url_subdirectory survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))

        expected_dirs = set()
        for root_dir, dir_lists, files_list in os.walk(TempDirPath):
            if os.path.dirname(root_dir) == TempDirPath:
                for one_file_name in dir_lists:
                    sub_path_name = os.path.join(root_dir, one_file_name)
                    expected_dirs.add(sub_path_name.replace("\\","/"))

        actual_dirs = set([str(one_path_url[0]).replace("\\","/") for one_path_url in query_result])
        print("actual_dirs=", actual_dirs)
        print("expected_dirs=", expected_dirs)
        self.assertTrue(actual_dirs == expected_dirs)

    def test_sparql_subdirectory_2(self):
        """Tests that a second-level directory is detected. """
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        dir_path = os.path.join(TempDirPath,
            "survol_temp_dir%d_1" % current_pid,
            "survol_temp_dir%d_2" % current_pid)
        os.makedirs(dir_path)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_2 survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))

        dir_path = dir_path.replace("\\","/")
        print("dir_path=", dir_path)

        actual_files = set([str(one_path_url[0]).replace("\\","/") for one_path_url in query_result])
        print("actual_files=", actual_files)
        self.assertTrue(dir_path in actual_files)

    actual_files = set(
        ['c:/users/rchateau/appdata/local/temp/_MEI37602/resources', 'c:/users/rchateau/appdata/local/temp/HP/AtStatus',
         'c:/users/rchateau/appdata/local/temp/survol_temp_dir10600_1/survol_temp_dir10600_2',
         'c:/users/rchateau/appdata/local/temp/LogMeInLogs/GoToMeeting',
         'c:/users/rchateau/appdata/local/temp/survol_temp_dir12240_1/survol_temp_dir12240_2',
         'c:/users/rchateau/appdata/local/temp/VSTelem/NgenPdb',
         'c:/users/rchateau/appdata/local/temp/survol_temp_dir10156_1/survol_temp_dir10156_2'])

    def test_sparql_subdirectory_3(self):
        """Tests that a third-level directory is detected. """
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        dir_path = os.path.join(TempDirPath,
            "survol_temp_dir%d_1" % current_pid,
            "survol_temp_dir%d_2" % current_pid,
            "survol_temp_dir%d_3" % current_pid)
        os.makedirs(dir_path)

        print("dir_path=", dir_path)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_3 a survol:CIM_Directory .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_2 survol:CIM_DirectoryContainsFile ?url_directory_3 .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_3 survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))

        dir_path = dir_path.replace("\\","/")
        print("dir_path=", dir_path)

        actual_files = set([str(one_path_url[0]).replace("\\","/") for one_path_url in query_result])
        print("actual_files=", actual_files)
        self.assertTrue(dir_path in actual_files)

    def test_sparql_subdirectory_4(self):
        """Tests that a third-level directory is detected. """
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        dir_path = os.path.join(TempDirPath,
            "survol_temp_dir%d_1" % current_pid,
            "survol_temp_dir%d_2" % current_pid,
            "survol_temp_dir%d_3" % current_pid,
            "survol_temp_dir%d_4" % current_pid)
        os.makedirs(dir_path)

        print("dir_path=", dir_path)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?subdirectory_name WHERE {
                ?url_directory_0 a survol:CIM_Directory .
                ?url_directory_1 a survol:CIM_Directory .
                ?url_directory_2 a survol:CIM_Directory .
                ?url_directory_3 a survol:CIM_Directory .
                ?url_directory_4 a survol:CIM_Directory .
                ?url_directory_0 survol:CIM_DirectoryContainsFile ?url_directory_1 .
                ?url_directory_1 survol:CIM_DirectoryContainsFile ?url_directory_2 .
                ?url_directory_2 survol:CIM_DirectoryContainsFile ?url_directory_3 .
                ?url_directory_3 survol:CIM_DirectoryContainsFile ?url_directory_4 .
                ?url_directory_0 survol:Name "%s" .
                ?url_directory_4 survol:Name ?subdirectory_name .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))

        dir_path = dir_path.replace("\\","/")
        print("dir_path=", dir_path)

        actual_files = set([str(one_path_url[0]).replace("\\","/") for one_path_url in query_result])
        print("actual_files=", actual_files)
        self.assertTrue(dir_path in actual_files)

    def test_sparql_subdirectory_down_up_4(self):
        rdflib_graph = CreateGraph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?directory_name WHERE {
                ?url_directory_0a a survol:CIM_Directory .
                ?url_directory_1a a survol:CIM_Directory .
                ?url_directory_2a a survol:CIM_Directory .
                ?url_directory_3a a survol:CIM_Directory .
                ?url_directory_4X a survol:CIM_Directory .
                ?url_directory_3b a survol:CIM_Directory .
                ?url_directory_2b a survol:CIM_Directory .
                ?url_directory_1b a survol:CIM_Directory .
                ?url_directory_0b a survol:CIM_Directory .
                ?url_directory_0a survol:CIM_DirectoryContainsFile ?url_directory_1a .
                ?url_directory_1a survol:CIM_DirectoryContainsFile ?url_directory_2a .
                ?url_directory_2a survol:CIM_DirectoryContainsFile ?url_directory_3a .
                ?url_directory_3a survol:CIM_DirectoryContainsFile ?url_directory_4X .
                ?url_directory_3b survol:CIM_DirectoryContainsFile ?url_directory_4X .
                ?url_directory_2b survol:CIM_DirectoryContainsFile ?url_directory_3b .
                ?url_directory_1b survol:CIM_DirectoryContainsFile ?url_directory_2b .
                ?url_directory_0b survol:CIM_DirectoryContainsFile ?url_directory_1b .
                ?url_directory_0a survol:Name "%s" .
                ?url_directory_0b survol:Name ?directory_name .
            }
        """ % (survol_namespace, TempDirPath)

        query_result = list(rdflib_graph.query(sparql_query))

        actual_files = [str(one_path_url[0]).replace("\\","/") for one_path_url in query_result]
        print("actual_files=", actual_files)
        self.assertTrue(actual_files[0] == TempDirPath)

    def test_sparql_parent_process(self):
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?the_ppid
            WHERE
            { ?url_proc survol:Handle %d .
              ?url_proc survol:ParentProcessId ?the_ppid .
              ?url_proc rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, current_pid)

        query_result = list(rdflib_graph.query(sparql_query))

        print("current_pid=", current_pid)
        parent_pid = psutil.Process(current_pid).ppid()
        print("parent_pid=", parent_pid)
        actual_pid = [str(one_pid[0]) for one_pid in query_result]
        print("actual_pid=", actual_pid)
        self.assertTrue(int(actual_pid[0]) == parent_pid)

    def test_sparql_sub_processes(self):
        rdflib_graph = CreateGraph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?process_id
            WHERE
            { ?url_proc survol:Handle ?process_id .
              ?url_proc survol:ParentProcessId %d .
              ?url_proc rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, os.getpid())

        query_result = list(rdflib_graph.query(sparql_query))

        actual_pids = set([int(str(one_pid[0])) for one_pid in query_result])
        print("actual_pids=", actual_pids)
        # Comparaison with the list of sub-processes of the current one.
        expected_pids = set([proc.pid for proc in psutil.Process(os.getpid()).children(recursive=False)])
        print("expected_pids=", expected_pids)
        self.assertTrue(actual_pids == expected_pids)

    def test_sparql_all_processes(self):
        rdflib_graph = CreateGraph()

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?process_id
            WHERE
            { ?url_proc survol:Handle ?process_id .
              ?url_proc rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace)

        # Comparison with the list of all processes.. This list must be built as close as possible
        # to the query execution, so the list do not change too much.
        expected_pids = set([proc.pid for proc in psutil.process_iter()])
        query_result = list(rdflib_graph.query(sparql_query))

        actual_pids = set([int(str(one_pid[0])) for one_pid in query_result])
        print("actual_pids=", actual_pids)

        print("expected_pids=", expected_pids)
        sets_difference =  [one_pid for one_pid in actual_pids if one_pid not in expected_pids]
        sets_difference += [one_pid for one_pid in expected_pids if one_pid not in actual_pids]
        print("sets_difference=", sets_difference)
        # Not too many processes were destroyed or deleted.
        self.assertTrue(len(sets_difference) < 10)
        current_pid = os.getpid()
        self.assertTrue(current_pid in actual_pids)
        self.assertTrue(current_pid in expected_pids)

    #@unittest.skip("Not yet")
    def test_sparql_grandparent_process(self):
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        print("current_pid=", current_pid)
        parent_pid = psutil.Process(current_pid).ppid()
        print("parent_pid=", parent_pid)
        grandparent_pid = psutil.Process(parent_pid).ppid()
        print("grandparent_pid=", grandparent_pid)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?pid_2
            WHERE
            {
              ?url_proc_0 survol:Handle %d .
              ?url_proc_0 survol:ParentProcessId ?pid_1 .
              ?url_proc_0 rdf:type survol:CIM_Process .
              ?url_proc_1 survol:Handle ?pid_1 .
              ?url_proc_1 survol:ParentProcessId ?pid_2 .
              ?url_proc_1 rdf:type survol:CIM_Process .
            }
        """ % (survol_namespace, current_pid)

        query_result = list(rdflib_graph.query(sparql_query))

        actual_pids = [int(str(one_pid[0])) for one_pid in query_result]
        print("actual_pids=", actual_pids)
        self.assertTrue(actual_pids[0] == grandparent_pid)

    def test_sparql_executable_process(self):
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        print("current_pid=", current_pid)

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc survol:CIM_ProcessExecutable ?url_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_datafile survol:Name ?datafile_name .
            }
        """ % (survol_namespace, current_pid)

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)

        datafile_name = [str(one_value[0]) for one_value in query_result][0]
        print("datafile_name=", datafile_name)
        print("sys.executable=", sys.executable)
        self.assertTrue(datafile_name == sys.executable)

    @unittest.skip("not yet")
    def test_sparql_processes_executing_python(self):
        rdflib_graph = CreateGraph()

        current_pid = os.getpid()
        print("current_pid=", current_pid)
        print("sys.executable=", sys.executable)

        # The Python variable sys.executable contains the currently running executable.
        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?process_pid
            WHERE
            {
              ?url_proc survol:Handle ?process_pid .
              ?url_proc survol:CIM_ProcessExecutable ?url_datafile .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_datafile rdf:type survol:CIM_DataFile .
              ?url_datafile survol:Name '%s' .
            }
        """ % (survol_namespace, sys.executable.replace("\\", "/"))

        query_result = list(rdflib_graph.query(sparql_query))
        print("query_result=", query_result)
        for s,p,o in query_result:
            print("    ", s, p, o)
        print("sparql_query=", sparql_query)

        # This must contain at least the current process.
        process_pids = [str(one_value[0]) for one_value in query_result]
        print("process_pids=", process_pids)
        self.assertTrue(current_pid in process_pids)



if __name__ == '__main__':
    unittest.main()

