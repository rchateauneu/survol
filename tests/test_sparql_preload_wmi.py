#!/usr/bin/env python

# Many SPARQL examples.
# http://api.talis.com/stores/space/items/tutorial/spared.html?query=SELECT+%3Fp+%3Fo%0D%0A{+%0D%0A++%3Chttp%3A%2F%2Fnasa.dataincubator.org%2Fspacecraft%2F1968-089A%3E+%3Fp+%3Fo%0D%0A}
#
# This is equivalent to:
# Special characters encoded in hexadecimal.
#
# The goal is to extract triples, for two different purposes:
# (1) Transform a Sparql query into WQL: This might work in very simple cases;, for WMI and WBEM.
# (2) Or identify which scripts should be run to feed a local triplestore and get useful data.
# Both purposes need the triples and the classes.

from __future__ import print_function

import os
import sys
import json
import unittest
import pkgutil

from init import *

update_test_path()

# This is what we want to test.
import lib_sparql
import lib_util
import lib_properties
import lib_kbase
import lib_wmi
import lib_sparql_callback_survol

# This can run only on Windows.
def setUpModule():
    try:
        import wmi
    except ImportError as err:
        raise unittest.SkipTest(str(err))

hard_coded_data_select = {
    "CIM_Process": [
        {"pid": 123, "ppid": 456, "user": "herself", "runs": "firefox.exe"},
        {"pid": 789, "ppid": 123, "user": "himself", "runs": "explorer.exe"},
    ],
    "CIM_DataFile": [
        {"owns": "herself", "Name": "C:/Program Files (x86)/Internet Explorer/iexplore.exe"},
        {"owns": "someone", "Name": "explorer.exe"},
    ],
    "CIM_Directory": [
        {"owns": "himself", "Name": "C:/Program Files"},
        {"owns": "herself", "Name": "C:/Program Files (x86)"},
        {"owns": "herself", "Name": "C:/Program Files (x86)/Internet Explorer"},
    ],
    "Win32_UserAccount": [
        {"uid": 111, "Name": "himself"},
        {"uid": 222, "Name": "herself"},
    ],
}


# The query function from lib_sparql module, returns RDF nodes.
# This is not very convenient to test.
# Therefore, for tests, this is a helper function which returns dict of strings,
# which are easier to compare.
def QueriesEntitiesToValuePairs(iter_entities_dicts):
    for one_entities_dict in iter_entities_dicts:

        one_entities_dict_qname = {}
        for variable_name, one_entity in one_entities_dict.items():
            #print("QueriesEntitiesToValuePairs one_entity=", one_entity)

            # Special attribute for debugging.
            dict_qname_value = {"__class__": one_entity.m_entity_class_name}
            for key_node, val_node in one_entity.m_predicate_object_dict.items():
                qname_key = lib_properties.PropToQName(key_node)
                str_val = str(val_node)
                dict_qname_value[qname_key] = str_val
            one_entities_dict_qname[variable_name] = dict_qname_value
        yield one_entities_dict_qname

def QueryKeyValuePairs(sparql_query, sparql_callback):
    iter_entities_dicts = lib_sparql.QueryEntities(None, sparql_query, sparql_callback)
    list_entities_dicts = list(iter_entities_dicts)
    iter_dict_objects = QueriesEntitiesToValuePairs(list_entities_dicts)
    list_dict_objects = list(iter_dict_objects)
    return list_dict_objects


def QuerySeeAlsoKeyValuePairs(grph, sparql_query, sparql_callback):
    WARNING("QuerySeeAlsoKeyValuePairs")
    iter_entities_dicts = lib_sparql.QuerySeeAlsoEntities(grph, sparql_query, sparql_callback)
    iter_dict_objects = QueriesEntitiesToValuePairs(iter_entities_dicts)
    list_dict_objects = list(iter_dict_objects)
    return list_dict_objects


def UrlToRdf(url_rdf):
    print("UrlToRdf url_rdf=",url_rdf)

    response = lib_util.survol_urlopen(url_rdf)
    doc_xml_rdf = response.read().decode("utf-8")

    print("doc_xml_rdf=",doc_xml_rdf)

    # We could use lib_client GetTripleStore because we just need to deserialize XML into RDF.
    # On the other hand, this would imply that a SparQL endpoint works just like that, and this is not sure.
    grphKBase = lib_kbase.triplestore_from_rdf_xml(doc_xml_rdf)
    return grphKBase

################################################################################


class SparqlCallWmiTest(unittest.TestCase):

    @staticmethod
    def __run_wmi_query(sparql_query):
        list_dict_objects = QueryKeyValuePairs(sparql_query, objectWmiSparqlCallbackApi )
        print("list_dict_objects len=",len(list_dict_objects))
        return list_dict_objects

    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_wmi_query not executed.")
    def test_wmi_query(self):

        dict_query_to_output_wmi =[
            ("""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type   survol:CIM_Process .
            }
            """ % CurrentPid,
               [
                   {"url_proc": {"Description": "python.exe", "Handle": str(CurrentPid)}},
               ]
            ),
            ("""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_dir survol:Name "C:"  .
              ?url_dir rdf:type survol:CIM_Directory .
            }
            """,
               [
                   {"url_dir": {"Name": "c:", 'CreationClassName': 'CIM_LogicalFile', 'CSName': CurrentMachine.upper()}},
               ]
            ),
            ("""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_dir rdf:type survol:Win32_UserAccount .
            }
            """,
               [
                   {"url_dir": {"Name": CurrentUsername}},
               ]
            ),
        ]

        # TODO: How to have backslashes in SparQL queries ???
        # "C:&#92;Users" 0x5C "C:%5CUsers"

        for sparql_query, expected_results in dict_query_to_output_wmi:
            print("===================================================")
            print(sparql_query)

            # TODO: Pass several callbacks, processed in a specific order ?
            list_dict_objects = SparqlCallWmiTest.__run_wmi_query(sparql_query)

            # There should not be too many data so a nested loop is OK.
            for one_expected_result in expected_results:
                for variable_name, expected_dict_variable in one_expected_result.items():
                    found_data = False
                    for one_actual_result in list_dict_objects:

                        actual_dict_variable = one_actual_result[variable_name]
                        print("actual_dict_variable=",actual_dict_variable)
                        found_data = dict(actual_dict_variable, **expected_dict_variable) == actual_dict_variable
                        if found_data:
                            print("Found")
                            break
                    if not found_data:
                        print("expected_dict_variable=",expected_dict_variable)
                    assert(found_data)


    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_wmi_to_rdf not executed.")
    def test_wmi_to_rdf(self):
        """This inserts the evaluation into a RDF triplestore. """

        sparql_query = """
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_dir rdf:type survol:CIM_DiskDrive .
            }
            """

        print(sparql_query)

        # TODO: Pass several callbacks, processed in a specific order ?
        itr_dict_objects = lib_sparql.QueryEntities(None, sparql_query, objectWmiSparqlCallbackApi )

        grph = lib_kbase.MakeGraph()

        for one_dict_objects in itr_dict_objects:
            for variable_name, key_value_nodes in one_dict_objects.items():
                # Only the properties of the ontology are used in the moniker
                # The moniker is built with a subset of properties, in a certain order.
                # In Survol's ontology, these properties are defined by each class'function EntityOntology()
                # These properties must be the same for all ontologies: WMI, WBEM and Survol,
                # otherwise objects could not be shared.
                print("variable_name=",variable_name)
                print("key_value_nodes=",key_value_nodes)
                wmiInstanceNode = lib_util.NodeUrl(key_value_nodes.m_subject_path)

                for key_node,value_node in key_value_nodes.m_predicate_object_dict.items():
                    grph.add((wmiInstanceNode,key_node,value_node))

    # "Associators of {CIM_Process.Handle=1780} where ClassDefsOnly"
    # => Win32_LogonSession Win32_ComputerSystem CIM_DataFile

    # "associators of {CIM_Process.Handle=1780} where resultclass=CIM_DataFile"
    # ...
    # Name: c:\program files\mozilla firefox\firefox.exe

    # "References of {CIM_Process.Handle=1780} where ClassDefsOnly"
    # => Win32_SessionProcess Win32_SystemProcesses CIM_ProcessExecutable

    # "references of {CIM_Process.Handle=1780} where resultclass=CIM_ProcessExecutable"
    # ...
    # Antecedent: \\RCHATEAU - HP\root\cimv2:CIM_DataFile.Name = "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
    # Dependent: \\RCHATEAU - HP\root\cimv2:Win32_Process.Handle = "1780"

    # ESCAPE BACKSLASH
    # "select * from CIM_DataFile where Name='c:\\program files\\mozilla firefox\\firefox.exe'"
    # ...
    # Name: c:\program files\mozilla firefox\firefox.exe
    # ...

    # "references of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} Where classdefsonly"
    # => CIM_DirectoryContainsFile Win32_SecuritySettingOfLogicalFile CIM_ProcessExecutable

    # "references of {CIM_DataFile='c:\\program files\\mozilla firefox\\firefox.exe'} Where resultclass = CIM_DirectoryContainsFile"
    # ...
    # GroupComponent: \\RCHATEAU - HP\root\cimv2:Win32_Directory.Name = "c:\\\\program files\\\\mozilla firefox\\"
    # PartComponent: \\RCHATEAU - HP\root\cimv2:CIM_DataFile.Name = "c:\\\\program files\\\\mozilla firefox\\\\firefox.exe"

    # BEWARE: With PowerShell, simple back-slash, DO NOT ESPACE back-slash !!!! Otherwise it only SEEMS to work.

    # "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'}"
    # => OK

    # "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} Where classdefsonly"
    # Win32_Directory Win32_LogicalFileSecuritySetting Win32_Process

    # "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} Where assocclass = CIM_DirectoryContainsFile"
    # EightDotThreeFileName: c:\program files\mozill~1
    # Name: c:\program files\mozilla firefox

    # "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} where resultclass=Win32_Process"
    # CommandLine: "C:\Program Files\Mozilla Firefox\firefox.exe"
    # Handle: 1780

    # "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} where resultclass=CIM_Process"
    # CommandLine: "C:\Program Files\Mozilla Firefox\firefox.exe"
    # Handle: 1780, idem.

    # THIS ONE IS OK:
    # "associators of {CIM_DataFile='c:\program files\mozilla firefox\firefox.exe'} where assocclass=CIM_ProcessExecutable

    # Le nom de l'associator sert de nom d'attribut. Indirectement, ca pourrait donner le nom de l'objet

    # INVERSEMENT:
    # gwmi -Query "associators of {CIM_Process.Handle=1780} where assocclass=CIM_ProcessExecutable"
    # ... renvoie aussi les DLLs.
    # Donc CIM_ProcessExecutable sert d'attribut pour les classes CIM_Process et CIM_DataFile.

    # {
    #   ?url_proc survol:Handle 12345  .
    #   ?url_proc rdf:type survol:CIM_Process .
    #   ?url_proc survol:CIM_ProcessExecutable ?url_sess .
    # }

    #        lib_sparq n est pas en mesure de traiter
    #Il faut le transformer ...
    #url_sess devient une sortie.
    #Si on n'a pas les toute sles variables...
    #Est-ce que lecallback peut etre recursif ?
    #
    #Normallement:
    #        yield url_proc=( object_path_node, dict_key_values )
    #
    #for object_path_node, dict_key_values in _callback_filter_all_sources(execute_query_callback, curr_input_entity, where_key_values_replaced):

    #Mais en fait:
    #       yield url_proc=( object_path_node, dict_key_values ) , url_sess=( object_path_node, dict_key_values )

    #Docn faudrait splitter deux fois en connaissant le contexte.
    #Dans quelle mesure ca s applique aussi a nos scripts ???
    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_wmi_associators_pid_to_files not executed.")
    def test_wmi_associators_pid_to_files(self):
        sparql_query = """
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
              ?url_proc survol:Handle %d .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file .
              ?url_file rdf:type survol:CIM_DataFile .
            }
            """ % CurrentPid

        list_dict_objects = SparqlCallWmiTest.__run_wmi_query(sparql_query)
        print("Elements:",len(list_dict_objects))

        # All dictionaries must have the same keys.
        for one_dict in list_dict_objects:
            assert sorted(one_dict.keys()) == ['url_file', 'url_proc']

        # This returns the current process and the executable and dlls it runs.
        pids_set = set([one_dict['url_proc']['Handle'] for one_dict in list_dict_objects])
        one_pid_only = int(pids_set.pop())
        assert one_pid_only == CurrentPid

        all_classes = set([one_dict['url_proc']['CreationClassName'] for one_dict in list_dict_objects])
        one_class_only = all_classes.pop()
        assert one_class_only == 'Win32_Process'

        one_machine_only = set( [ one_dict['url_file']['CSName'] for one_dict in list_dict_objects] )
        assert one_machine_only.pop().upper() == CurrentMachine.upper()

        all_extensions = set( [ one_dict['url_file']['Extension'] for one_dict in list_dict_objects] )
        print(all_extensions)
        assert all_extensions == set( ['dll', 'exe', 'pyd' ] )

        # Unique dlls and exe names.
        all_dlls = set( [ one_dict['url_file']['Name'] for one_dict in list_dict_objects] )
        assert len(all_dlls) == len(list_dict_objects)


    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_wmi_associators_executable_to_files not executed.")
    def test_wmi_associators_executable_to_files(self):
        sparql_query = """
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
              ?url_proc survol:Caption "firefox.exe"  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file .
              ?url_file rdf:type survol:CIM_DataFile .
            }"""

        list_dict_objects = SparqlCallWmiTest.__run_wmi_query(sparql_query)

        for one_dict in list_dict_objects:
            assert sorted(one_dict.keys()) == ['url_file', 'url_proc']

        print(list_dict_objects[0])



    # Must be transformed into:
    # ASSOCIATORS OF {CIM_Process.Handle=xx} WHERE RESULTCLASS=CIM_DataFile ASSOCCLASS=CIM_ProcessExecutable
    # SELECT FROM CIM_DataFile WHERE Name="c:/program files/mozilla firefox/firefox.exe"
    #
    # Ou bien ???
    # ASSOCIATORS OF {CIM_DataFile.Name="c:/program files/mozilla firefox/firefox.exe"} WHERE RESULTCLASS=CIM_Process ASSOCCLASS=CIM_ProcessExecutable
    # SELECT FROM CIM_Process WHERE Handle=xyz
    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_wmi_associators_pid_to_exe not executed.")
    def test_wmi_associators_pid_to_exe(self):
        sparql_query = """
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
              ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:CIM_ProcessExecutable ?url_file .
              ?url_file survol:Name 'c:/program files/mozilla firefox/firefox.exe' .
              ?url_file rdf:type survol:CIM_DataFile .
            }
            """ % CurrentPid

        list_dict_objects = QueryKeyValuePairs(sparql_query, objectWmiSparqlCallbackApi )

        # The extra filter on CIM_DataFile.Name is not checked.

        print("Elements:",len(list_dict_objects))

        # All dictionaries must have the same keys.
        for one_dict in list_dict_objects:
            assert sorted(one_dict.keys()) == ['url_file', 'url_proc']

        # This returns the current process and the executable and dlls it runs.
        pids_set = set([one_dict['url_proc']['Handle'] for one_dict in list_dict_objects])
        one_pid_only = int(pids_set.pop())
        assert one_pid_only == CurrentPid

        all_classes_proc = set([one_dict['url_proc']['CreationClassName'] for one_dict in list_dict_objects])
        one_class_only = all_classes_proc.pop()
        assert one_class_only == 'Win32_Process'

        all_classes_file = set([one_dict['url_file']['CreationClassName'] for one_dict in list_dict_objects])
        one_class_only = all_classes_file.pop()
        assert one_class_only == 'CIM_LogicalFile'

        one_machine_only = set( [ one_dict['url_file']['CSName'] for one_dict in list_dict_objects] )
        assert one_machine_only.pop().upper() == CurrentMachine.upper()

        all_extensions = set( [ one_dict['url_file']['Extension'] for one_dict in list_dict_objects] )
        print(all_extensions)
        assert all_extensions == set( ['dll', 'exe', 'pyd' ] )

        # Unique dlls and exe names.
        all_dlls = set( [ one_dict['url_file']['Name'] for one_dict in list_dict_objects] )
        assert len(all_dlls) == len(list_dict_objects)


    @unittest.skipIf(not pkgutil.find_loader('wmi'), "wmi cannot be imported. test_wmi_associators_all_procs_to_firefox not executed.")
    def test_wmi_associators_all_procs_to_firefox(self):
        # TODO: How to have backslashes in SparQL queries ???
        # "C:&#92;Users" 0x5C "C:%5CUsers"
        sparql_query = """
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
              ?url_proc survol:Handle ?proc_id  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_file survol:CIM_ProcessExecutable ?url_proc .
              ?url_file survol:Name '%s' .
              ?url_file rdf:type survol:CIM_DataFile .
            }
            """ % r"c:\\program files\\mozilla firefox\\firefox.exe"

        assert objectWmiSparqlCallbackApi != None
        list_dict_objects = QueryKeyValuePairs(sparql_query, objectWmiSparqlCallbackApi )

        for one_dict in list_dict_objects:
            assert sorted(one_dict.keys()) == ['url_file', 'url_proc']
            assert one_dict['url_file']['Name'] == "c:\\\\program files\\\\mozilla firefox\\\\firefox.exe"
            assert one_dict['url_proc']['ExecutablePath'] == "C:\\\\Program Files\\\\Mozilla Firefox\\\\firefox.exe"
            assert one_dict['url_proc']['CreationClassName'] == "Win32_Process"


class SparqlPreloadServerWMITest(unittest.TestCase):
    """
    Test the Sparql server which works on Survol data.
    The attributes in the SparQL query must match the ontology of the query callback function.
    """

    @staticmethod
    def __load_wmi_query(sparql_query):
        print("sparql_query=",sparql_query)

        url_sparql = RemoteTestAgent + "/survol/sparql_preload_wmi.py?query=" + lib_util.urllib_quote(sparql_query)

        rdf_data = UrlToRdf(url_sparql)
        return rdf_data

    def test_Win32_UserAccount(self):
        """Looks for current user"""
        sparql_query="""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
                ?url_user rdf:type survol:Win32_UserAccount .
            }
            """

        grphKBase = self.__load_wmi_query(sparql_query)

        # We should find at least the current user.
        # TODO: Uppercase problem: Hostnames by convention should be in lowercase.
        # RFC-4343: DNS should be case insensitive.
        # Lower case has been the standard usage ever since there has been domain name servers.
        # expectedPath= '\\rchateau-hp\root\cimv2:Win32_UserAccount.Domain="rchateau-hp",Name="rchateau"'
        # rdfSubject= '\\RCHATEAU-HP\root\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="rchateau"'
        expectedPath = '\\\\%s\\root\\cimv2:Win32_UserAccount.Domain="%s",Name="%s"' % ( CurrentMachine, CurrentMachine, CurrentUsername )
        foundPath = False
        print("expectedPath=",expectedPath)
        for rdfSubject, rdfPredicate, rdfObject in grphKBase:
            if rdfSubject.upper() == expectedPath.upper():
                foundPath = True
                break
            print("rdfSubject=",rdfSubject)
        assert(foundPath)

    def test_Win32_LogicalDisk(self):
        sparql_query="""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_disk rdf:type survol:Win32_LogicalDisk .
              ?url_disk survol:DeviceID "C:" .
            }
            """

        grphKBase = self.__load_wmi_query(sparql_query)

        # "\\RCHATEAU-HP\root\cimv2:Win32_LogicalDisk.DeviceID="C:" http://primhillcomputers.com/survol/Name C:"
        expectedPath = '\\\\%s\\root\\cimv2:Win32_LogicalDisk.DeviceID="C:"' % ( CurrentMachine )
        print("expectedPath=",expectedPath)
        for rdfSubject, rdfPredicate, rdfObject in grphKBase:
            print(rdfSubject, rdfPredicate, rdfObject)
            # TODO: Should compare

    def test_CIM_DataFile(self):
        sparql_query="""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
              ?url_file survol:Name "c:/program files/mozilla firefox/firefox.exe" .
              ?url_file rdf:type survol:CIM_DataFile .
            }
        """

        grphKBase = self.__load_wmi_query(sparql_query)

        for rdfSubject, rdfPredicate, rdfObject in grphKBase:
            print(rdfSubject, rdfPredicate, rdfObject)
            # TODO: Should compare


    def test_CIM_Process(self):
        sparql_query="""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:Name "python.exe" .
            }
            """

        grphKBase = self.__load_wmi_query(sparql_query)

        for rdfSubject, rdfPredicate, rdfObject in grphKBase:
            print(rdfSubject, rdfPredicate, rdfObject)
            # TODO: Should compare


    @staticmethod
    def run_query_survol(sparql_query):
        print("sparql_query=", sparql_query)

        url_sparql = RemoteTestAgent + "/survol/sparql_preload_all.py?query=" + lib_util.urllib_quote(sparql_query)

        rdf_data = UrlToRdf(url_sparql)

        # All the triples must be in the result set where each element is transformed to a string
        # print(rdf_data)

        str_actual_data = set()
        for subject, predicate, object in rdf_data:
            str_subject = str(subject)
            str_predicate = str(predicate)
            str_object = str(object)
            str_actual_data.add((str_subject, str_predicate, str_object))
        return str_actual_data

    # PROBLEM: WMI writes domain names as "RCHATEAU-HP" or "rchateau-HP".
    # expected_triples = [('\\\\rchateau-hp\\root\\cimv2:Win32_UserAccount.Domain="rchateau-hp",Name="Guest"',
    #                      'http://primhillcomputers.com/survol#Domain', 'rchateau-hp'), (
    #                     '\\\\rchateau-hp\\root\\cimv2:Win32_UserAccount.Domain="rchateau-hp",Name="Guest"',
    #                     'http://primhillcomputers.com/survol#Name', 'Guest')]
    # str_actual_data = set([('\\\\RCHATEAU-HP\\root\\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="Guest"',
    #                         'http://primhillcomputers.com/survol#Caption', 'rchateau-HP\\\\Guest'), ])

    array_survol_queries = [
        [
            """
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            {
                ?url_user rdf:type survol:Win32_UserAccount .
                ?url_user rdfs:seeAlso "WMI" .
            }
            """,
            [
                (
                    '\\\\%s\\root\\cimv2:Win32_UserAccount.Domain="%s",Name="Guest"' % (CurrentMachine, CurrentMachine),
                    'http://primhillcomputers.com/survol#Domain',
                    CurrentMachine
                ),
                (
                    '\\\\%s\\root\\cimv2:Win32_UserAccount.Domain="%s",Name="Guest"' % (CurrentMachine, CurrentMachine),
                    'http://primhillcomputers.com/survol#Name',
                    'Guest'
                ),
            ]
        ],
    ]

    # PROBLEM: WMI writes domain names as "RCHATEAU-HP" or "rchateau-HP".
    # Therefore the same test is done with a case conversion.
    # expected_triples= [
    #     ('\\\\rchateau-hp\\root\\cimv2:Win32_UserAccount.Domain="rchateau-hp",Name="Guest"','http://primhillcomputers.com/survol#Domain', 'rchateau-hp'),
    #     ('\\\\rchateau-hp\\root\\cimv2:Win32_UserAccount.Domain="rchateau-hp",Name="Guest"', 'http://primhillcomputers.com/survol#Name', 'Guest')]
    # str_actual_data= {
    #     ('\\\\RCHATEAU-HP\\root\\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="Guest"', 'http://primhillcomputers.com/survol#Domain', 'rchateau-HP'),
    #     ('\\\\RCHATEAU-HP\\root\\cimv2:Win32_UserAccount.Domain="rchateau-HP",Name="Guest"', 'http://primhillcomputers.com/survol#Name', 'Guest'),
    @unittest.skipIf( True, "WMI hostname converted to uppercase.")
    def test_preload_server_survol(self):
        for sparql_query, expected_triples in self.array_survol_queries:
            str_actual_data = self.run_query_survol(sparql_query)

            print("expected_triples=", expected_triples)
            print("str_actual_data=", str_actual_data)
            for one_triple in expected_triples:
                self.assertTrue(one_triple in str_actual_data)

    def test_preload_server_survol_case_insensitive(self):
        for sparql_query, expected_triples in self.array_survol_queries:
            str_actual_data = self.run_query_survol(sparql_query)
            str_actual_data_upper = [ (s.upper(), p.upper(), o.upper()) for s, p, o in str_actual_data]

            print("expected_triples=", expected_triples)
            print("str_actual_data=", str_actual_data)
            for s, p, o in expected_triples:
                test_result = ((s.upper(), p.upper(), o.upper()) in str_actual_data_upper)
                self.assertTrue(test_result, "Result")





try:
    objectWmiSparqlCallbackApi = lib_wmi.WmiSparqlCallbackApi()
except:
    objectWmiSparqlCallbackApi = None

# FIXME: Is it really called ?? Consider setupModule and tearDownModule
def setUp():
    assert objectWmiSparqlCallbackApi != None

prefix_to_callbacks = {
    #"HardCoded": HardcodeSparqlCallbackApi(),
    "WMI": objectWmiSparqlCallbackApi,
    "survol": lib_sparql_callback_survol.SurvolSparqlCallbackApi(),
}

unittestCallback = lib_sparql.SwitchCallbackApi(prefix_to_callbacks)

class SparqlSeeAlsoTest(unittest.TestCase):
    @staticmethod
    def compare_list_queries(array_survol_queries):
        for sparql_query, one_expected_dict in array_survol_queries:
            print("sparql_query=",sparql_query)

            list_dict_objects = QuerySeeAlsoKeyValuePairs( None, sparql_query, unittestCallback)

            # The expected object must be a subset of one of the returned objects.
            print("list_dict_objects=",list_dict_objects)
            print("GOLD=",one_expected_dict)

            expected_keys = one_expected_dict.keys()
            found = False
            for one_dict_objects in list_dict_objects:
                actual_keys = one_dict_objects.keys()
                assert actual_keys == expected_keys
                # print("TEST=",one_dict_objects)

                # This returns the first pair of different elements.
                def diff_dictionary(sub_dict, main_dict):
                    for sub_key in sub_dict:
                        sub_val = sub_dict[sub_key]
                        try:
                            main_val = main_dict[sub_key]
                        except KeyError:
                            return (sub_key, sub_val, None)
                        if sub_val != main_val:
                            return (sub_key, sub_val, main_val)
                    return (None, None, None)

                # Maybe each of the select objects are only sub_dicts of the actual result.
                all_diff = {
                    var_key: diff_dictionary(one_expected_dict[var_key], one_dict_objects[var_key])
                    for var_key in expected_keys }

                if all_diff == {var_key:(None, None, None) for var_key in expected_keys} :
                    found = True
                    break

            print("all_diff=",all_diff)
            assert found

    def test_see_also(self):
        CurrentFile = __file__.replace("\\","/")
        array_survol_queries=[
            [
                """
                SELECT *
                WHERE
                { ?url_proc survol:Handle %d  .
                  ?url_proc rdf:type survol:CIM_Process .
                  ?url_proc rdfs:seeAlso "WMI" .
                }
                """ % CurrentPid,
                {'url_proc': {'CSName': 'RCHATEAU-HP', 'Name': 'python.exe',
                              'ProcessId': str(CurrentPid), 'Handle': str(CurrentPid),
                              'OSCreationClassName': 'Win32_OperatingSystem',
                              '__class__': 'CIM_Process', 'rdf-schema#isDefinedBy': 'WMI', 'ParentProcessId': str(CurrentParentPid),
                              'Caption': 'python.exe', 'CSCreationClassName': 'Win32_ComputerSystem', 'Description': 'python.exe',
                              'ExecutablePath': 'C:\\\\Python27\\\\python.exe', 'CreationClassName': 'Win32_Process', }},
            ],

               ["""
                SELECT *
                WHERE
                { ?url_proc survol:Name "%s" .
                  ?url_proc rdf:type survol:CIM_DataFile .
                  ?url_proc rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
                }
                """ % CurrentFile,
                {'url_proc': {'__class__': 'CIM_DataFile', 'Name': CurrentFile} }
            ],

            ["""
                SELECT *
                WHERE
                { ?url_proc survol:Name "/usr/lib/systemd/systemd-journald" .
                  ?url_proc rdf:type survol:CIM_DataFile .
                  ?url_proc rdfs:seeAlso "survol:CIM_DataFile/mapping_processes" .
                }
                """,
                {'url_proc': {'__class__': 'CIM_DataFile', 'Name': '/usr/lib/systemd/systemd-journald'}},
            ],
            ["""
                SELECT *
                WHERE
                { ?url_proc survol:Handle %d  .
                  ?url_proc rdf:type survol:CIM_Process .
                  ?url_proc rdfs:seeAlso <http://vps516494.ovh.net/Survol/survol/entity.py?xid=CIM_Process.Handle=29&mode=rdf> .
                }
                """ % CurrentPid,
                {'url_proc': {'username': 'rchateau',
                              'Handle': str(CurrentPid),
                              # 'rdf-schema#isDefinedBy': 'CIM_Process:SelectFromWhere',
                              'parent_pid': str(CurrentParentPid),
                              '__class__': 'CIM_Process'}}
            ],

            ["""
                SELECT *
                WHERE
                { ?url_proc survol:Handle %d  .
                  ?url_proc rdf:type survol:CIM_Process .
                  ?url_proc rdfs:seeAlso "survol:CIM_Process/process_open_files" .
                  ?url_proc rdfs:seeAlso "survol:CIM_Process/single_pidstree" .
                  ?url_proc rdfs:seeAlso "survol:CIM_Process/languages/python/current_script" .
                }
                """ % CurrentPid,
                {'url_proc': {'Handle': str(CurrentPid), '__class__': 'CIM_Process'}},
            ],

        ]

        self.compare_list_queries(array_survol_queries)


    def test_see_also_associator(self):
        #CurrentPid=8000
        # This checks that the current process runs the Python executable.
        array_survol_queries_associator=[

            ["""
            SELECT *
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc rdfs:seeAlso "WMI" .
              ?url_proc survol:CIM_ProcessExecutable ?url_file  .
              ?url_file rdfs:seeAlso "WMI" .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
            }
            """ % CurrentPid,
            {
                'url_proc': {'Handle': str(CurrentPid), '__class__': 'CIM_Process'},
                'url_file': {'CSName': 'RCHATEAU-HP',
                          '__class__': 'CIM_DataFile', 'rdf-schema#isDefinedBy': 'WMI',
                          'Name': 'c:\\\\windows\\\\system32\\\\clbcatq.dll',
                          'CSCreationClassName': 'Win32_ComputerSystem', 'CreationClassName': 'CIM_LogicalFile'}
            },

            # The CIM_Process objects are returned by Survol and by WMI. Their triples are merged by RDF.
            # 'url_proc': { 'Name': 'python.exe', 'ProcessId': '13292', 'OSCreationClassName': 'Win32_OperatingSystem', '__class__': 'CIM_Process',}
            ],

            ["""
            SELECT *
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc survol:CIM_ProcessExecutable ?url_file  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc rdfs:seeAlso "WMI" .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file rdfs:seeAlso "survol:CIM_DataFile/file_stat" .
            }
            """ % CurrentPid,
             {'url_proc': {'CSName': 'RCHATEAU-HP', 'Name': 'python.exe', 'ProcessId': str(CurrentPid),
                           'Handle': str(CurrentPid),
                           'OSCreationClassName': 'Win32_OperatingSystem',
                           '__class__': 'CIM_Process', 'rdf-schema#isDefinedBy': 'WMI',
                           'ParentProcessId': str(CurrentParentPid), 'Caption': 'python.exe',
                           'CSCreationClassName': 'Win32_ComputerSystem',
                           'Description': 'python.exe',
                           'ExecutablePath': 'C:\\\\Python27\\\\python.exe',
                           'CreationClassName': 'Win32_Process'},
              'url_file': {'CSName': 'RCHATEAU-HP',
                           'FSCreationClassName': 'Win32_FileSystem',
                           '__class__': 'CIM_DataFile',
                           'rdf-schema#isDefinedBy': 'WMI',
                           'CSCreationClassName': 'Win32_ComputerSystem',
                           'CreationClassName': 'CIM_LogicalFile'}},
             ],

             ["""
                SELECT *
                WHERE
                { ?url_proc survol:Handle %d  .
                  ?url_proc rdf:type survol:CIM_Process .
                  ?url_file rdfs:seeAlso "WMI" .
                  ?url_file rdf:type survol:CIM_DataFile .
                  ?url_file survol:Name "%s" .
                  ?url_file survol:CIM_ProcessExecutable ?url_proc  .
                }
                """ % ( CurrentPid, sys.executable.replace("\\","/") ),
                {'url_proc': {'CSName': 'RCHATEAU-HP', 'Name': 'python.exe', 'ProcessId': str(CurrentPid),
                              'Handle': str(CurrentPid),
                              'OSCreationClassName': 'Win32_OperatingSystem',
                              '__class__': 'CIM_Process',
                              'rdf-schema#isDefinedBy': 'WMI',
                              'ParentProcessId': str(CurrentParentPid),
                              'Caption': 'python.exe',
                              'CSCreationClassName': 'Win32_ComputerSystem', 'Description': 'python.exe',
                              'ExecutablePath': 'C:\\\\Python27\\\\python.exe',
                              'CreationClassName': 'Win32_Process', },
                 'url_file': {'CSName': 'RCHATEAU-HP',
                              'FSCreationClassName': 'Win32_FileSystem',
                              'Description': 'c:\\\\python27\\\\python.exe', '__class__': 'CIM_DataFile',
                              'rdf-schema#isDefinedBy': 'WMI',
                              'Name': 'c:\\\\python27\\\\python.exe',
                              'FileType': 'Application', 'Drive': 'c:', 'Extension': 'exe',
                              'Caption': 'c:\\\\python27\\\\python.exe',
                              'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'python',
                              'CreationClassName': 'CIM_LogicalFile'}},
                ],

            ["""
                SELECT *
                WHERE
                { ?url_proc survol:Handle %d  .
                  ?url_proc survol:CIM_ProcessExecutable ?url_file  .
                  ?url_proc rdf:type survol:CIM_Process .
                  ?url_proc rdfs:seeAlso "WMI" .
                  ?url_file rdf:type survol:CIM_DataFile .
                }
                """ % CurrentPid,
                {'url_proc': {'username': 'rchateau', 'Handle': str(CurrentPid), 'parent_pid': str(CurrentParentPid), '__class__': 'CIM_Process'},
                 'url_file': {'CSName': 'RCHATEAU-HP', '__class__': 'CIM_DataFile', 'CreationClassName': 'CIM_LogicalFile' }},
            ],

        ]

        self.compare_list_queries(array_survol_queries_associator)

    def test_see_also_directories(self):
        """Combinations of directories and files"""
        array_survol_directories_queries=[

        ["""
            SELECT *
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA rdfs:seeAlso "WMI" .
              ?url_fileA survol:Name "C:/Windows"  .
              ?url_fileA survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileB survol:Name "C:/Windows/regedit.exe"  .
              ?url_fileB rdfs:seeAlso "WMI" .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""",
            {
                'url_fileA': {
                    'FSCreationClassName': 'Win32_FileSystem',
                    '__class__': 'CIM_Directory', 'rdf-schema#isDefinedBy': 'WMI',
                    'Name': 'c:\\\\windows',
                    'FileType': 'File Folder', 'Drive': 'c:', 'Extension': '',
                    'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'windows',
                    'CreationClassName': 'CIM_LogicalFile'},
               'url_fileB': {
                    'CSName': 'RCHATEAU-HP', 'FSCreationClassName': 'Win32_FileSystem',
                    '__class__': 'CIM_DataFile', 'rdf-schema#isDefinedBy': 'WMI',
                    'Name': 'c:\\\\windows\\\\regedit.exe',
                    'CreationClassName': 'CIM_LogicalFile'}
            }
        ],

        ["""
            SELECT *
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA rdfs:seeAlso "WMI" .
              ?url_fileB survol:Win32_SubDirectory ?url_fileA  .
              ?url_fileB rdf:type survol:CIM_Directory .
              ?url_fileB rdfs:seeAlso "WMI" .
              ?url_fileC survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileC survol:Name "C:/Windows/System32/cmd.exe"  .
              ?url_fileC rdfs:seeAlso "WMI" .
              ?url_fileC rdf:type survol:CIM_DataFile .
            }""",
            {
                'url_fileA': { 'FSCreationClassName': 'Win32_FileSystem',
                     'rdf-schema#isDefinedBy': 'WMI',
                     'Name': 'c:\\\\windows\\\\system32\\\\appmgmt',
                     'CSCreationClassName': 'Win32_ComputerSystem',
                     'FileName': 'appmgmt', 'CreationClassName': 'CIM_LogicalFile'},
                'url_fileC': {'FSCreationClassName': 'Win32_FileSystem',
                     '__class__': 'CIM_DataFile',
                     'Path': '\\\\windows\\\\system32\\\\',
                     'rdf-schema#isDefinedBy': 'WMI',
                     'Name': 'c:\\\\windows\\\\system32\\\\cmd.exe',
                     'FileType': 'Application', 'Drive': 'c:', 'Extension': 'exe',
                     'CSCreationClassName': 'Win32_ComputerSystem',
                     'CreationClassName': 'CIM_LogicalFile'},
                'url_fileB': {'CSName': 'RCHATEAU-HP',
                     'Description': 'c:\\\\windows\\\\system32',
                     'rdf-schema#isDefinedBy': 'WMI',
                     'Name': 'c:\\\\windows\\\\system32', 'FileType': 'File Folder',
                     'Drive': 'c:', 'Extension': '',
                     'CSCreationClassName': 'Win32_ComputerSystem',
                     'CreationClassName': 'CIM_LogicalFile'}}
            ],

        ["""
            SELECT *
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA rdfs:seeAlso "WMI" .
              ?url_fileB survol:CIM_DirectoryContainsFile ?url_fileA  .
              ?url_fileB survol:Name "C:/Windows/System32/cmd.exe"  .
              ?url_fileB rdfs:seeAlso "WMI" .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""",

         {'url_fileA': { 'FSCreationClassName': 'Win32_FileSystem',
                         'Description': 'c:\\\\windows\\\\system32',
                         'EightDotThreeFileName': 'c:\\\\windows\\\\system32',
                         'rdf-schema#isDefinedBy': 'WMI',
                         'Name': 'c:\\\\windows\\\\system32',
                         'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'system32',
                         'CreationClassName': 'CIM_LogicalFile'},
           'url_fileB': {'FSCreationClassName': 'Win32_FileSystem',
                         'Description': 'c:\\\\windows\\\\system32\\\\cmd.exe',
                         '__class__': 'CIM_DataFile',
                         'Path': '\\\\windows\\\\system32\\\\',
                         'rdf-schema#isDefinedBy': 'WMI',
                         'Name': 'c:\\\\windows\\\\system32\\\\cmd.exe',
                         'FileType': 'Application',
                         'Drive': 'c:', 'Extension': 'exe',
                         'CSCreationClassName': 'Win32_ComputerSystem'}
          }
        ],

        # TODO: MAYBE USE WQL LIKE IF SPARQL STRING CONTAINS '%'

        ["""
            SELECT *
            WHERE
            { ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA rdfs:seeAlso "WMI" .
              ?url_fileB survol:Win32_SubDirectory ?url_fileA  .
              ?url_fileB survol:Name "C:/Windows/System32"  .
              ?url_fileB rdfs:seeAlso "WMI" .
              ?url_fileB rdf:type survol:CIM_Directory .
            }""",

        {
            'url_fileA':{'FSCreationClassName': 'Win32_FileSystem', 'AccessMask': '1179817',
                         '__class__': 'CIM_Directory',
                         'LastModified': '20160304001306.619093+000',
                         'Path': '\\\\windows\\\\system32\\\\',
                         'rdf-schema#isDefinedBy': 'WMI',
                         'Name': 'c:\\\\windows\\\\system32\\\\appmgmt', 'FileType': 'File Folder',
                         'Drive': 'c:', 'Extension': '',
                         'CSCreationClassName': 'Win32_ComputerSystem',
                         'FileName': 'appmgmt', 'CreationClassName': 'CIM_LogicalFile'},
           'url_fileB': {'FSCreationClassName': 'Win32_FileSystem',
                         '__class__': 'CIM_Directory',
                         'rdf-schema#isDefinedBy': 'WMI',
                         'Name': 'c:\\\\windows\\\\system32',
                         'FileType': 'File Folder',
                         'Drive': 'c:', 'Extension': '', 'Caption': 'c:\\\\windows\\\\system32',
                         'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'system32',
                         'CreationClassName': 'CIM_LogicalFile'},
        }

        ],

        # BEWARE: This also returns the top-directory.
        ["""
            SELECT *
            WHERE
            { ?url_dirA survol:Name "C:/Windows"  .
              ?url_dirA rdf:type survol:CIM_Directory .
              ?url_dirA rdfs:seeAlso "WMI" .
              ?url_dirA survol:Win32_SubDirectory ?url_dirB  .
              ?url_dirB rdfs:seeAlso "WMI" .
              ?url_dirB rdf:type survol:CIM_Directory .
            }""",
         {'url_dirA': {'CSName': 'RCHATEAU-HP',
                     'FSCreationClassName': 'Win32_FileSystem',
                     '__class__': 'CIM_Directory', 'rdf-schema#isDefinedBy': 'WMI',
                     'Name': 'c:\\\\windows',
                     'FileType': 'File Folder', 'Drive': 'c:', 'Extension': '',
                     'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'windows',
                     'CreationClassName': 'CIM_LogicalFile'},
          'url_dirB': {'CSName': 'RCHATEAU-HP',
                     'FSCreationClassName': 'Win32_FileSystem',
                     '__class__': 'CIM_Directory', 'rdf-schema#isDefinedBy': 'WMI',
                     'Name': 'c:\\\\windows\\\\drivers', 'FileType': 'File Folder',
                     'Drive': 'c:', 'Extension': '','CreationClassName': 'CIM_LogicalFile'}
          },
        ],

        ["""
            SELECT *
            WHERE
            { ?url_fileA survol:Name "C:/Windows"  .
              ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA rdfs:seeAlso "WMI" .
              ?url_fileA survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileB rdfs:seeAlso "WMI" .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""",
             {'url_fileA': {'CSName': 'RCHATEAU-HP',
                             'FSCreationClassName': 'Win32_FileSystem',
                             '__class__': 'CIM_Directory', 'rdf-schema#isDefinedBy': 'WMI',
                             'Name': 'c:\\\\windows',
                             'FileType': 'File Folder', 'Drive': 'c:', 'Extension': '',
                             'CSCreationClassName': 'Win32_ComputerSystem', 'FileName': 'windows',
                             'CreationClassName': 'CIM_LogicalFile'},
               'url_fileB': {'CSName': 'RCHATEAU-HP',
                             'FSCreationClassName': 'Win32_FileSystem',
                             '__class__': 'CIM_DataFile',
                             'rdf-schema#isDefinedBy': 'WMI', 'Name': 'c:\\\\windows\\\\notepad.exe',
                             'FileType': 'Application',
                             'Drive': 'c:', 'Extension': 'exe',
                             'CSCreationClassName': 'Win32_ComputerSystem',
                             'CreationClassName': 'CIM_LogicalFile'}},
         ],

        ]

        self.compare_list_queries(array_survol_directories_queries)

    # Some query examples taken from https://codyburleson.com/sparql-examples-list-classes/
    def test_meta_information(self):
        """Special Survol seeAlso pathes"""
        CurrentFile = __file__.replace("\\","/")
        array_survol_queries=[
            # This returns all WMI classes.
            ["""
                SELECT *
                WHERE
                { ?url_class rdf:type rdfs:Class .
                  ?url_class rdfs:seeAlso "WMI" .
                }
                """,
                {'url_class': {
                    '22-rdf-syntax-ns#type': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
                    'rdf-schema#seeAlso': 'WMI',
                    '__class__': 'Class',
                    'rdf-schema#isDefinedBy': 'WMI',
                    'Name': 'Win32_UserProfile'}},
            ],

            # All possible properties
            ["""
                SELECT *
                WHERE
                { ?url_attribute rdf:type rdf:Property .
                  ?url_attribute rdfs:seeAlso "WMI" .
                }
                """,
                {'url_attribute': {}},
            ],

            # List subclasses.
            ["""
                SELECT *
                WHERE
                { ?url_subclass rdfs:subClassOf ?url_class .
                  ?url_class rdfs:seeAlso "WMI" .
                  ?url_subclass rdfs:seeAlso "WMI" .
                }
                """,
                {'url_class': {},'url_subclass': {}},
            ],

            # All properties of CIM_Process
            ["""
                SELECT *
                WHERE
                { ?url_property rdf:type rdf:Property .
                  ?url_property rdfs:domain survol:CIM_Process .
                  ?url_property rdfs:seeAlso "WMI" .
                }
                """,
                {'url_property': {}},
            ],

            # TODO: Test rdfs:range
        ]

        for sparql_query, one_expected_dict in array_survol_queries:
            print("sparql_query=",sparql_query)

            list_dict_objects = QuerySeeAlsoKeyValuePairs(None, sparql_query, unittestCallback)

            print("list_dict_objects=",list_dict_objects)
            print("GOLD=",one_expected_dict)
            assert(one_expected_dict in list_dict_objects)




# This works: gwmi -Query 'xxxxx'
# ASSOCIATORS OF {Win32_Process.Handle=1520}
# ASSOCIATORS OF {CIM_Process.Handle=1520}
# ASSOCIATORS OF {CIM_Process.Handle=1520} where classdefsonly
# ASSOCIATORS OF {CIM_Process.Handle=1520} where resultclass=CIM_DataFile

# For the associators, the exact keys are needed, i.e. ite object path.

if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

