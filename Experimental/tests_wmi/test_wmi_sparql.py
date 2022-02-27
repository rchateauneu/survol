import sys
import io
import os
import logging
import pytest

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
    print("CIM_ProcessExecutable=", wmi_sparql.classes_dictionary['CIM_ProcessExecutable'])
    assert wmi_sparql.classes_dictionary['CIM_ProcessExecutable'] == {
        'Antecedent': 'ref:CIM_DataFile', 'BaseAddress': 'uint64', 'Dependent': 'ref:CIM_Process',
        'GlobalProcessCount': 'uint32', 'ModuleInstance': 'uint32', 'ProcessCount': 'uint32'}
    assert wmi_sparql.keys_dictionary['CIM_DataFile'] == ('Name',)


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


def no_check(query_results):
    return True


samples_list["CIM_Directory"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_directory
    where {
    ?my_directory rdf:type cim:CIM_Directory .
    ?my_directory cim:Name "C:" .
    }
    """,
    [
        _CimObject(VARI('my_directory'), 'CIM_Directory', {'Name': LITT('C:')}),
    ],
    no_check
)

samples_list["CIM_Process"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_name ?my_process_handle
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle ?my_process_handle .
    ?my_process cim:Name ?my_process_name .
    }
    """,
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle'), 'Name': VARI('my_process_name')}),
    ],
    no_check
)

samples_list["CIM_DirectoryContainsFile with Directory=C:"] = (
    """
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
    """,
    [
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': LITT('C:')}),
    ],
    no_check
)

samples_list["CIM_DirectoryContainsFile with File=KERNEL32.DLL"] = (
    """
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
    """,
    [
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': LITT("C:\\\\WINDOWS\\\\System32\\\\KERNEL32.DLL")}),
    ],
    no_check
)

samples_list["CIM_ProcessExecutable with Antecedent=KERNEL32.DLL"] = (
    """
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
    """,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': LITT(r'C:\\WINDOWS\\System32\\KERNEL32.DLL')}),
    ],
    no_check
)

current_pid = os.getpid()

samples_list["CIM_ProcessExecutable with Dependent=current process"] = (
    """
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
    """ % current_pid,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT('%d' % current_pid)}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
    ],
    no_check
)

samples_list["CIM_Process with Handle= current process"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?my_process_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Handle %s .
    ?my_process cim:Caption ?my_process_caption .
    }
    """ % current_pid,
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT(current_pid), 'Caption': VARI('my_process_caption')}),
    ],
    no_check
)

samples_list["Win32_Directory CIM_DirectoryContainsFile CIM_DirectoryContainsFile"] = (
    """
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
    """,
    [
        _CimObject(VARI('my_assoc_dir1'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir1'), 'PartComponent': VARI('my_dir2')}),
        _CimObject(VARI('my_assoc_dir2'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir2'), 'PartComponent': VARI('my_dir3')}),
        _CimObject(VARI('my_dir1'), 'Win32_Directory', {'Name': LITT('C:')}),
        _CimObject(VARI('my_dir2'), 'Win32_Directory', {}),
        _CimObject(VARI('my_dir3'), 'Win32_Directory', {'Name': VARI('my_dir_name3')}),
    ],
    no_check
)

samples_list["CIM_ProcessExecutable CIM_DirectoryContainsFile Handle=current_pid"] = (
    """
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
    """ % current_pid,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': LITT(current_pid)}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
    ],
    no_check
)

samples_list["CIM_ProcessExecutable full scan"] = (
    """
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
    """,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {'Handle': VARI('my_process_handle')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
    ],
    no_check
)

samples_list["CIM_ProcessExecutable CIM_DirectoryContainsFile"] = (
    """
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
    """,
    [
        _CimObject(VARI('my_assoc'), 'CIM_ProcessExecutable', {'Dependent': VARI('my_process'), 'Antecedent': VARI('my_file')}),
        _CimObject(VARI('my_assoc_dir'), 'CIM_DirectoryContainsFile', {'GroupComponent': VARI('my_dir'), 'PartComponent': VARI('my_file')}),
        _CimObject(VARI('my_process'), 'CIM_Process', {}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Name': VARI('my_file_name')}),
        _CimObject(VARI('my_dir'), 'CIM_Directory', {'Name': VARI('my_dir_name')}),
    ],
    no_check
)

samples_list["CIM_Process CIM_DataFile Same Caption"] = (
    """
    prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
    prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
    select ?same_caption
    where {
    ?my_process rdf:type cim:CIM_Process .
    ?my_process cim:Caption ?same_caption .
    ?my_file rdf:type cim:CIM_DataFile .
    ?my_file cim:Caption ?same_caption .
    }
    """,
    [
        _CimObject(VARI('my_process'), 'CIM_Process', {'Caption': VARI('same_caption')}),
        _CimObject(VARI('my_file'), 'CIM_DataFile', {'Caption': VARI('same_caption')}),
    ],
    no_check
)


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

    custom_eval = wmi_sparql.CustomEvalEnvironment(test_description, test_details[0], test_details[1])

    custom_eval.run_tests()


def test_wmi():
    for test_description, test_details in samples_list.items():
        #if test_description != "CIM_ProcessExecutable with Antecedent=KERNEL32.DLL":
        #    continue

        shuffle_lst_objects(test_description, test_details)

"""
Queries to test:
The chain of chains of classes and propeerties linking two properties with a name containing X and Y.
In other words: What links two concepts.
"""

if __name__ == '__main__':
    test_classes_dictionary()
    test_keys_lists()
    test_wmi()