import sys
import io
import os
import logging
import pytest

import rdflib
import wmi

import wmi_sparql
from wmi_sparql import _CimObject
from wmi_sparql import VARI
from wmi_sparql import LITT
from wmi_sparql import _contains_all_keys
from wmi_sparql import _contains_one_key
from wmi_sparql import _generate_wql_code

samples_list = dict()


def test_classes_dictionary():
    # On-the-fly check of the classes dictionary.
    print("")
    print("CIM_ProcessExecutable=", wmi_sparql.classes_dictionary['CIM_ProcessExecutable'])
    assert wmi_sparql.classes_dictionary['CIM_ProcessExecutable'] == {
        'Antecedent': 'ref:CIM_DataFile', 'BaseAddress': 'uint64', 'Dependent': 'ref:CIM_Process',
        'GlobalProcessCount': 'uint32', 'ModuleInstance': 'uint32', 'ProcessCount': 'uint32'}
    assert wmi_sparql.keys_dictionary['CIM_DataFile'] == ('Name',)


ontology_filename = "wmi_ontology.xml"


def test_create_ontology(ontology_filename):
    rdf_graph = rdflib.Graph()
    wmi_sparql._convert_ontology_to_rdf(wmi.WMI(), rdf_graph)
    rdf_graph.serialize(destination=ontology_filename, format='xml')


def to_literals(results):
    def tuple_literals(one_tuple):
        return tuple(one_term.toPython() for one_term in one_tuple)
    return [tuple_literals(one_tuple) for one_tuple in results]


def test_content_ontology(ontology_filename):
    """
    This checks the presence of some very important triples.
    :param ontology_filename: The filename containing the ontology in RDF/XML format.
    :return: Nothing
    """

    rdf_graph = rdflib.Graph()
    rdf_graph.parse(ontology_filename)
    assert len(list(rdf_graph.triples((rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessExecutable"]), None, None)))) == 4
    assert len(list(rdf_graph.triples((rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessExecutable"]), wmi_sparql.property_association_node, None)))) == 1

    query_all_classes = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        select distinct ?the_class
        where {
        ?the_class rdf:type rdfs:Class .
        }
        """
    results_all_classes = set(rdf_graph.query(query_all_classes))
    print("All classes")
    if False:
        for x in results_all_classes:
            print(x)
    assert (rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessExecutable"]),) in results_all_classes

    if False:
        print("Plain loop on all classes")
        for s, p, o in rdf_graph.triples((rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessExecutable"]), None, None)):
            print(s, p, o)

    query_CIM_ProcessExecutable = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?prop
        where {
        cim:CIM_ProcessExecutable ?prop ?obj .
        }
        """
    print("CIM_ProcessExecutable")
    results_CIM_ProcessExecutable = set(rdf_graph.query(query_CIM_ProcessExecutable))
    for x in results_CIM_ProcessExecutable:
        print(x)
    assert (rdflib.URIRef(wmi_sparql.LDT["is_association"]),) in results_CIM_ProcessExecutable
    assert (rdflib.namespace.RDF.type,) in results_CIM_ProcessExecutable
    assert (rdflib.namespace.RDFS.label,) in results_CIM_ProcessExecutable
    assert (rdflib.namespace.RDFS.comment,) in results_CIM_ProcessExecutable
    assert len(results_CIM_ProcessExecutable) == 4
    if False:
        print("Plain loop on CIM_ProcessExecutable")
        for s, p, o in rdf_graph.triples((rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessExecutable"]), None, None)):
            print(s, p, o)

    # Classes which are associators.
    query_associators = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?class_node
        where {
        ?class_node cim:is_association ?obj .
        }
        """
    print("Associators")
    results_associators = set(rdf_graph.query(query_associators))
    if False:
        for x in results_associators:
            print(x)
    print("Number of associators:", len(results_associators))
    assert (rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessExecutable"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["CIM_DirectoryContainsFile"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_COMApplicationClasses"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_ApplicationCommandLine"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["CIM_ProcessThread"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_DependentService"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_SystemServices"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_UserInDomain"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_SystemUsers"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_SessionProcess"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["CIM_ProductSoftwareFeatures"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_SystemProcesses"]),) in results_associators
    assert (rdflib.URIRef(wmi_sparql.LDT["Win32_SubDirectory"]),) in results_associators
    if False:
        print("Plain loop on associators")
        for s, p, o in rdf_graph.triples((None, rdflib.URIRef(wmi_sparql.LDT["is_association"]), None)):
            print(s, p, o)

    # Properties of associator classes.
    query_associators_properties = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?class_name ?property_name
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label ?class_name .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:label ?property_name .
        }
        """
    print("Properties of associators")
    results_associators_properties = set(rdf_graph.query(query_associators_properties))
    results_associators_properties = to_literals(results_associators_properties)
    assert ("CIM_DirectoryContainsFile", "CIM_DirectoryContainsFile.GroupComponent",) in results_associators_properties
    assert ("CIM_DirectoryContainsFile", "CIM_DirectoryContainsFile.PartComponent",) in results_associators_properties

    # Range of properties of associator CIM_DirectoryContainsFile.
    query_CIM_DirectoryContainsFile_properties_range = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?property_name ?range_class_node
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label "CIM_DirectoryContainsFile" .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:range ?range_class_node .
        ?property_node rdfs:label ?property_name .
        }
        """
    print("Range of properties of associator CIM_DirectoryContainsFile")
    results_CIM_DirectoryContainsFile_properties_range = rdf_graph.query(query_CIM_DirectoryContainsFile_properties_range)
    for x in results_CIM_DirectoryContainsFile_properties_range:
        print(x)
    assert (rdflib.term.Literal("CIM_DirectoryContainsFile.GroupComponent"), rdflib.URIRef(wmi_sparql.LDT["CIM_Directory"]),) in results_CIM_DirectoryContainsFile_properties_range
    assert (rdflib.term.Literal("CIM_DirectoryContainsFile.PartComponent"), rdflib.URIRef(wmi_sparql.LDT["CIM_DataFile"]),) in results_CIM_DirectoryContainsFile_properties_range

    # Name of class of range of properties of associator Win32_ShareToDirectory.
    query_Win32_ShareToDirectory_properties_range = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?property_name ?range_class_name
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label "Win32_ShareToDirectory" .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:range ?range_class_node .
        ?property_node rdfs:label ?property_name .
        ?range_class_node rdfs:label ?range_class_name .
        }
        """
    print("Range of properties of associator Win32_ShareToDirectory")
    results_Win32_ShareToDirectory_properties_range = rdf_graph.query(query_Win32_ShareToDirectory_properties_range)
    results_Win32_ShareToDirectory_properties_range = to_literals(results_Win32_ShareToDirectory_properties_range)
    for x in results_Win32_ShareToDirectory_properties_range:
        print(x)
    assert ("Win32_ShareToDirectory.Share", "Win32_Share",) in results_Win32_ShareToDirectory_properties_range
    assert ("Win32_ShareToDirectory.SharedElement", "CIM_Directory",) in results_Win32_ShareToDirectory_properties_range

    # Associators pointing to a CIM_DataFile.
    query_associators_to_CIM_DataFile = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?class_name ?property_name
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label ?class_name .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:range ?range_class_node .
        ?property_node rdfs:label ?property_name .
        ?range_class_node rdfs:label "CIM_DataFile" .
        }
        """
    print("Associators to CIM_DataFile")
    results_associators_to_CIM_DataFile = rdf_graph.query(query_associators_to_CIM_DataFile)
    results_associators_to_CIM_DataFile = to_literals(results_associators_to_CIM_DataFile)
    assert ('CIM_DirectoryContainsFile', 'CIM_DirectoryContainsFile.PartComponent', ) in results_associators_to_CIM_DataFile
    assert ('Win32_PnPSignedDriverCIMDataFile', 'Win32_PnPSignedDriverCIMDataFile.Dependent', ) in results_associators_to_CIM_DataFile
    assert ('Win32_LogicalProgramGroupItemDataFile', 'Win32_LogicalProgramGroupItemDataFile.Dependent', ) in results_associators_to_CIM_DataFile
    assert ('CIM_ProcessExecutable', 'CIM_ProcessExecutable.Antecedent', ) in results_associators_to_CIM_DataFile
    assert ('Win32_PrinterDriverDll', 'Win32_PrinterDriverDll.Antecedent', ) in results_associators_to_CIM_DataFile
    assert ('Win32_ClientApplicationSetting', 'Win32_ClientApplicationSetting.Client', ) in results_associators_to_CIM_DataFile
    assert ('Win32_CIMLogicalDeviceCIMDataFile', 'Win32_CIMLogicalDeviceCIMDataFile.Dependent', ) in results_associators_to_CIM_DataFile

    # Name of class of range of properties of associator CIM_ProcessThread.
    query_Win32_CIM_ProcessThread_properties_range = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?property_name ?range_class_name
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label "CIM_ProcessThread" .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:range ?range_class_node .
        ?property_node rdfs:label ?property_name .
        ?range_class_node rdfs:label ?range_class_name .
        }
        """
    print("Range of properties of associator CIM_ProcessThread")
    results_CIM_ProcessThread_properties_range = rdf_graph.query(query_Win32_CIM_ProcessThread_properties_range)
    results_CIM_ProcessThread_properties_range = to_literals(results_CIM_ProcessThread_properties_range)
    for x in results_CIM_ProcessThread_properties_range:
        print(x)
    assert ("CIM_ProcessThread.GroupComponent", "CIM_Process",) in results_CIM_ProcessThread_properties_range
    assert ("CIM_ProcessThread.PartComponent", "CIM_Thread",) in results_CIM_ProcessThread_properties_range

    # Associators pointing to a CIM_Thread.
    query_associators_to_CIM_Thread = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?class_name ?property_name
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label ?class_name .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:range ?range_class_node .
        ?property_node rdfs:label ?property_name .
        ?range_class_node rdfs:label "CIM_Thread" .
        }
        """
    print("Associators to CIM_Thread")
    results_associators_to_CIM_Thread = rdf_graph.query(query_associators_to_CIM_Thread)
    results_associators_to_CIM_Thread = to_literals(results_associators_to_CIM_Thread)
    for x in results_associators_to_CIM_Thread:
        print(x)
    assert ('CIM_ProcessThread', 'CIM_ProcessThread.PartComponent', ) in results_associators_to_CIM_Thread

    # Associators pointing to CIM_Process.
    query_associators_to_CIM_Process = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?class_name ?property_name
        where {
        ?class_node cim:is_association ?obj .
        ?class_node rdfs:label ?class_name .
        ?property_node rdfs:domain ?class_node .
        ?property_node rdfs:range ?range_class_node .
        ?property_node rdfs:label ?property_name .
        ?range_class_node rdfs:label "CIM_Process" .
        }
        """
    print("Associators to CIM_Process")
    results_associators_to_CIM_Process = rdf_graph.query(query_associators_to_CIM_Process)
    results_associators_to_CIM_Process = to_literals(results_associators_to_CIM_Process)
    for x in results_associators_to_CIM_Process:
        print(x)
    assert ('CIM_OSProcess', 'CIM_OSProcess.PartComponent') in results_associators_to_CIM_Process
    assert ('CIM_ProcessExecutable', 'CIM_ProcessExecutable.Dependent') in results_associators_to_CIM_Process
    assert ('CIM_ProcessThread', 'CIM_ProcessThread.GroupComponent') in results_associators_to_CIM_Process


def test_keys_lists():
    assert _contains_all_keys("CIM_Directory", {"Name": None})
    assert _contains_all_keys("CIM_Directory", {"Name": None, "Anything": None})
    assert not _contains_all_keys("CIM_Directory", {"Nothing": None})
    assert _contains_all_keys("CIM_DirectoryContainsFile", {"GroupComponent": None, "PartComponent": None})
    assert _contains_all_keys("CIM_DirectoryContainsFile", {"GroupComponent": None, "PartComponent": None, "xyz": None})
    assert not _contains_all_keys("CIM_DirectoryContainsFile", {"PartComponent": None, "xyz": None})

    assert _contains_one_key("CIM_Directory", {"Name": None})
    assert _contains_one_key("CIM_Directory", {"Name": None, "Anything": None})
    assert not _contains_one_key("CIM_Directory", {"SomethingElse": None})
    assert _contains_one_key("CIM_DirectoryContainsFile", {"GroupComponent": None, "PartComponent": None})
    assert _contains_one_key("CIM_DirectoryContainsFile", {"GroupComponent": None, "PartComponent": None, "xyz": None})
    assert _contains_one_key("CIM_DirectoryContainsFile", {"GroupComponent": None, "xyz": None})
    assert not _contains_one_key("CIM_DirectoryContainsFile", {"xyz": None})


#def test_code_generation():
#    my_stream = io.StringIO()
#    shuffled_lst_objects = "LKJ:LKJ"

#    code_description = _generate_wql_code(my_stream, self.m_output_variables, shuffled_lst_objects)

#################################################################################################

if False:
    samples_list["Metadata1"] = (
        """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?same_caption
        where {
        ?my_process rdf:type cim:CIM_Process .
        ?my_process ?cim_property ?same_caption .
        ?cim_property rdf:name ?cim_property_name .
        }
        """,
        [
            _CimObject(VARI('my_process'), 'CIM_Process', {'Caption': VARI('same_caption')}),
            _CimObject(VARI('my_file'), 'CIM_DataFile', {'Caption': VARI('same_caption')}),
        ],
        no_check
    )

#################################################################################################

class TestBase(type):
    subclasses = dict()

    # def __new__(cls, name, bases, dct):
    #def __new__(cls, name, bases, dct):
    #    #    #x = super().__new__(cls, name, bases, dct)
    #    x = super().__new__(cls, name, bases, dct)
    #    #    cls.subclasses[cls.label] = x
    #    print("New", name, type(x), type(cls))
    #    return x

    def __init__(cls, name, bases, dct):
        print("Init", name, type(cls))
        cls.subclasses[cls.label] = cls

class Testing_CIM_Directory(metaclass=TestBase):
    label = "CIM_Directory"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_directory
    where {
    ?my_directory rdf:type cim:CIM_Directory .
    ?my_directory cim:Name "C:" .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_directory'), 'CIM_Directory', {'Name': LITT('C:')}),
    ]

    def checker(query_results):
        assert len(query_results) == 1


class Testing_CIM_Process(metaclass=TestBase):
    """
    This selects all process ids and their names.
    """
    label = "CIM_Process"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_name ?my_process_handle
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle ?my_process_handle .
    ?my_process cim:Name ?my_process_name .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle'), 'Name': VARI('my_process_name')}),
    ]

    def checker(query_results):
        """
        It must contain at least the current process.
        :return:
        """
        # This should be something like "python.exe"
        process_name = os.path.basename(sys.executable)
        assert (rdflib.term.Literal(process_name), rdflib.term.Literal(str(current_pid))) in query_results


class Testing_CIM_DirectoryContainsFile_WithDir(metaclass=TestBase):
    label = "CIM_DirectoryContainsFile with Directory=C:"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_file_name
    where {
    ?my_assoc_dir rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir cim:GroupComponent ?my_dir .
    ?my_assoc_dir cim:PartComponent ?my_file .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    ?my_dir rdf:type cim:Win32_Directory .
    ?my_dir cim:Name 'C:' .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': LITT('C:')}),
    ]

    def checker(query_results):
        # one_result_dict= {'my_file': <wmi_sparql.PseudoWmiObject object at 0x000002094C304820>,
        # 'my_dir': <_wmi_object: b'\\\\LAPTOP-R89KG6V1\\root\\cimv2:Win32_Directory.Name="C:"'>,
        # 'my_file_name': 'C:\\swapfile.sys',
        # 'my_assoc_dir': <wmi_sparql.PseudoWmiObject object at 0x000002094C3049D0>}

        # This checks that all variables are present in all results.
        expected_keys = set(['my_dir_name', 'my_assoc_dir', 'my_file', 'my_dir', 'my_file_name'])
        for one_result in query_results:
            assert set(one_result.keys()) == expected_keys


class Testing_CIM_DirectoryContainsFile_WithFile(metaclass=TestBase):
    label = "CIM_DirectoryContainsFile with File=KERNEL32.DLL"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_dir_name
    where {
    ?my_assoc_dir rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir cim:GroupComponent ?my_dir .
    ?my_assoc_dir cim:PartComponent ?my_file .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name "C:\\\\WINDOWS\\\\System32\\\\KERNEL32.DLL" .
    ?my_dir rdf:type cim:Win32_Directory .
    ?my_dir cim:Name ?my_dir_name .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': LITT("C:\\\\WINDOWS\\\\System32\\\\KERNEL32.DLL")}),
    ]

    def checker(query_results):
        # This checks that all variables are present.
        expected_keys = set(['my_dir_name', 'my_assoc_dir', 'my_file', 'my_dir'])
        for one_result in query_results:
            assert set(one_result.keys()) == expected_keys


class Testing_CIM_ProcessExecutable_WithAntecedent(metaclass=TestBase):
    label = "CIM_ProcessExecutable with Antecedent=KERNEL32.DLL"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_handle
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle ?my_process_handle .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name "C:\\\\WINDOWS\\\\System32\\\\KERNEL32.DLL" .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': LITT(r'C:\\WINDOWS\\System32\\KERNEL32.DLL')}),
    ]

    def checker(query_results):
        # This checks that all variables are present.
        expected_keys = set(['my_assoc', 'my_process', 'my_file', 'my_process_handle'])
        for one_result in query_results:
            assert set(one_result.keys()) == expected_keys


current_pid = os.getpid()

class Testing_CIM_ProcessExecutable_WithDependent(metaclass=TestBase):
    label = "CIM_ProcessExecutable with Dependent=current process"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_file_name
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle "%d" .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    }
    """ % current_pid
    expected_objects = [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT('%d' % current_pid)}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
    ]

    def checker(query_results):
        # This checks that all variables are present.
        expected_keys = set(['my_assoc', 'my_process', 'my_file', 'my_file_name'])
        for one_result in query_results:
            assert set(one_result.keys()) == expected_keys


class Testing_CIM_Process_WithHandle(metaclass=TestBase):
    label = "CIM_Process with Handle= current process"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle %s .
    ?my_process cim:Caption ?my_process_caption .
    }
    """ % current_pid
    expected_objects = [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT(current_pid), 'Caption': VARI('my_process_caption')}),
    ]

    def checker(query_results):
        assert False


class Testing_Win32_Directory_CIM_DirectoryContainsFile_CIM_DirectoryContainsFile(metaclass=TestBase):
    label = "Win32_Directory CIM_DirectoryContainsFile CIM_DirectoryContainsFile"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_dir_name3
    where {
    ?my_dir1 rdf:type cim:Win32_Directory .
    ?my_dir1 cim:Name "C:" .
    ?my_assoc_dir1 rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir1 cim:GroupComponent ?my_dir1 .
    ?my_assoc_dir1 cim:PartComponent ?my_dir2 .
    ?my_dir2 rdf:type cim:Win32_Directory .
    ?my_assoc_dir2 rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir2 cim:GroupComponent ?my_dir2 .
    ?my_assoc_dir2 cim:PartComponent ?my_dir3 .
    ?my_dir3 rdf:type cim:Win32_Directory .
    ?my_dir3 cim:Name ?my_dir_name3 .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_assoc_dir1'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir1'), 'PartComponent': VARI('my_dir2')}),
        _CimObject(VARI('my_assoc_dir2'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir2'), 'PartComponent': VARI('my_dir3')}),
        _CimObject(VARI('my_dir1'), 'Win32_Directory', {'Name': LITT('C:')}),
        _CimObject(VARI('my_dir2'), 'Win32_Directory', {}),
        _CimObject(VARI('my_dir3'), 'Win32_Directory', {'Name': VARI('my_dir_name3')}),
    ]

    def checker(query_results):
        assert False


class Testing_CIM_ProcessExecutable_CIM_DirectoryContainsFile_WithHandle(metaclass=TestBase):
    label = "CIM_ProcessExecutable CIM_DirectoryContainsFile Handle=current_pid"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_dir_name
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_assoc_dir rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir cim:GroupComponent ?my_dir .
    ?my_assoc_dir cim:PartComponent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle "%d" .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    ?my_dir rdf:type cim:Win32_Directory .
    ?my_dir cim:Name ?my_dir_name .
    }
    """ % current_pid
    expected_objects = [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT(current_pid)}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
    ]

    def checker(query_results):
        assert False


class Testing_CIM_ProcessExecutable_FullScan(metaclass=TestBase):
    label = "CIM_ProcessExecutable full scan"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_file_name ?my_process_handle
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle ?my_process_handle .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
    ]

    def checker(query_results):
        assert False


class Testing_CIM_ProcessExecutable_CIM_DirectoryContainsFile(metaclass=TestBase):
    label = "CIM_ProcessExecutable CIM_DirectoryContainsFile"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_dir_name
    where {
    ?my_assoc rdf:type cim:CIM_ProcessExecutable .
    ?my_assoc cim:Dependent ?my_process .
    ?my_assoc cim:Antecedent ?my_file .
    ?my_assoc_dir rdf:type cim:CIM_DirectoryContainsFile .
    ?my_assoc_dir cim:GroupComponent ?my_dir .
    ?my_assoc_dir cim:PartComponent ?my_file .
    ?my_process rdf:type cim:CIM_Process .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Name ?my_file_name .
    ?my_dir rdf:type cim:Win32_Directory .
    ?my_dir cim:Name ?my_dir_name .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
    ],

    def checker(query_results):
        assert False


class Testing_CIM_Process_CIM_DataFile_SameCaption(metaclass=TestBase):
    label = "CIM_Process CIM_DataFile Same Caption"
    query = """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?same_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Caption ?same_caption .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Caption ?same_caption .
    }
    """
    expected_objects = [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Caption': VARI('same_caption')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Caption': VARI('same_caption')}),
    ]

    def checker(query_results):
        assert False


# CHERCHER DES PROPERTIES QUI EXISTENT AIILLEURS POUR FAIRE DES FEDEREATED QUERIES:
# EMAIL <=> FOAF ETC...

#################################################################################################

"""
Ajouter un test avec deux full scans mais au lieu de faire deux boucles imbriquees, on les fait separament:
select oa from ClassA:
    select ob from ClassB:
        select oc from ClassC where oc.f1 = oa.f1 and oc.f2 = ob.f2

... devient:
la = select oa from ClassA
lb = select ob from ClassB
for oa in la:
    for ob in lb:
        select oc from ClassC where oc.f1 = oa.f1 and oc.f2 = ob.f2
        
        
Autrement dit, on deplace les boucles de WMI vers Python.
C'est a dire qu on decouple une boucle en deux phases:
- Aller chercher le generateur ou la liste.
- Boucler dessus.

Ca permet alors d'entrecroiser deux boucles qui n'ont pas de dependance.
Creer une forme intermediaire pour exprimer ceci
"""

#################################################################################################


def shuffle_lst_objects(test_description, test_details):
    print("")
    print("#" * 50, test_description)
    sys.stdout.flush()

    custom_eval = wmi_sparql.CustomEvalEnvironment(test_description, test_details.query, test_details.expected_objects)

    query_results = custom_eval.run_query_in_rdflib()
    print("query_results", query_results)
    test_details.checker(query_results)


def test_sparql_data():
    for test_description, test_details in TestBase.subclasses.items():
        # CIM_ProcessExecutable full scan
        #if test_description != "CIM_Process CIM_DataFile Same Caption":
        #    continue

        shuffle_lst_objects(test_description, test_details)

"""
Queries to test:
The chain of chains of classes and properties linking two properties with a name containing X and Y.
In other words: What links two concepts.
"""

if __name__ == '__main__':
    # test_create_ontology(ontology_filename)
    # test_content_ontology(ontology_filename)
    """
    Seulement si le fichier n est pas la sinon on initialise avec.
    Charger les ontologies dans le graph.
    Faire les tests de meta data.
    L'insertion dans le graph peut se faire a partir d'un graph rdflib car de toute facon on l'a sos la main,
    et bien separer l execution sparql: On peut la faire dans le custom_eval vers un endpoint.
    """
    #test_classes_dictionary()
    #test_keys_lists()
    test_sparql_data()