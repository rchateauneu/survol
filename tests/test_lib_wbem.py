#!/usr/bin/env python

from __future__ import print_function

import os
import sys
import json
import unittest
import pkgutil

from init import *

update_test_path()

# This is what we want to test.
import lib_wbem
import lib_kbase
import lib_properties

################################################################################

# Similar function in test_lib_wmi.py
def GetElementAsString(dict_key_values, property_name):
    property_node = lib_properties.MakeProp(property_name)
    value_node = dict_key_values[property_node]
    value_literal = str(value_node)
    return value_literal

# This is shared by all tests. This class contains all the methods needed
# to execute a Spqral query in a CIM-like context.
callback_object = lib_wbem.WbemSparqlCallbackApi()

class LibWbemTest(unittest.TestCase):
    @unittest.skipIf(not is_linux_wbem(), "No WBEM.")
    def test_local_ontology(self):
        # This test can run only if the local machine has a WBEM server.
        map_classes, map_attributes = lib_wbem.ExtractWbemOntology()
        self.assertTrue("CIM_Process" in map_classes)
        self.assertTrue("CIM_DataFile" in map_classes)
        self.assertTrue("CIM_Directory" in map_classes)

        self.assertTrue("Handle" in map_attributes)
        self.assertTrue("Name" in map_attributes)
        self.assertTrue("Caption" in map_attributes)

    @unittest.skipIf(is_travis_machine(), "Test is too slow for Travis")
    @unittest.skipIf(not has_wbem(), "pywbem cannot be imported. test_remote_ontology not executed.")
    def test_remote_ontology(self):
        """Very slow test: It displays the entire list of classes and their properties."""
        # In contrast to another test which remotely connect to a Survol agent,
        # which then makes a local TCP/IP connection to its local WBEM Cimom,
        # this test directly connects to the remote Cimom.
        wbem_connection = lib_wbem.WbemConnection(SurvolWbemCimom)

        map_classes, map_attributes = lib_wbem.ExtractRemoteWbemOntology(wbem_connection)
        self.assertTrue( "CIM_Process" in map_classes)
        self.assertTrue("Handle" in map_attributes)

    @unittest.skipIf(not has_wbem(), "pywbem cannot be imported. test_remote_ontology not executed.")
    def test_remote_namespaces(self):
        """At least the defaultnamespace must be there."""
        wbem_connection = lib_wbem.WbemConnection(SurvolWbemCimom)
        namespaces_dict = lib_wbem.EnumNamespacesCapabilities(wbem_connection)
        self.assertTrue("root/cimv2" in namespaces_dict)

    @unittest.skipIf(not is_linux_wbem(), "WBEM not usable here")
    def test_sparql_callback_select_current_process(self):
        filtered_where_key_values = {
            "Handle": CurrentPid
        }
        grph = lib_kbase.MakeGraph()

        iterator_objects = callback_object.CallbackSelect(grph, "CIM_Process", "WBEM", filtered_where_key_values)
        list_objects = list(iterator_objects)

        for object_path, dict_key_values in list_objects:
            DEBUG(object_path)
            DEBUG(dict_key_values)
        self.assertTrue(len(list_objects) == 1)

        # object.path=//vps516494.ovh.net/root/cimv2:PG_UnixProcess.CSName="vps516494.localdomain",Handle="23446",OSCreationClassName="CIM_OperatingSystem",CreationClassName="PG_UnixProcess",CSCreationClassName="CIM_UnitaryComputerSystem",OSName="Fedora"
        # dict_key_values={
        # u'Parameters': [u'/usr/bin/python2'],
        # rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'): rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CIM_Process'),
        # u'CSName': u'vps516494.localdomain', u'RealUserID': Uint64(cimtype='uint64', minvalue=0, maxvalue=18446744073709551615, 1001),
        # u'ProcessNiceValue': Uint32(cimtype='uint32', minvalue=0, maxvalue=4294967295, 0),
        # u'Handle': u'23446', u'Description': u'/usr/bin/python2',
        # u'OSCreationClassName': u'CIM_OperatingSystem',
        # u'Name': u'pytest',
        # u'Caption': u'pytest',
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#seeAlso'): rdflib.term.Literal(u'WBEM'),
        # u'KernelModeTime': Uint64(cimtype='uint64', minvalue=0, maxvalue=18446744073709551615, 15000),
        # u'ParentProcessID': u'30088', u'ExecutionState': Uint16(cimtype='uint16', minvalue=0, maxvalue=65535, 6),
        # u'CSCreationClassName': u'CIM_UnitaryComputerSystem',
        # u'UserModeTime': Uint64(cimtype='uint64', minvalue=0, maxvalue=18446744073709551615, 79000),
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#isDefinedBy'): rdflib.term.Literal(u'WBEM'),
        # u'CreationClassName': u'PG_UnixProcess'}

        self.assertTrue(GetElementAsString(dict_key_values, 'Handle') == str(CurrentPid))
        # Spelled "ParentProcessId" in WMI.
        self.assertTrue(GetElementAsString(dict_key_values, 'ParentProcessID') == str(CurrentParentPid))
        self.assertTrue(GetElementAsString(dict_key_values, 'CSCreationClassName') == 'CIM_UnitaryComputerSystem')

    @unittest.skipIf(not is_linux_wbem(), "WBEM not usable here")
    def test_sparql_callback_select_computer(self):
        filtered_where_key_values = {
            #"Name": CurrentMachine
        }
        grph = lib_kbase.MakeGraph()

        # dict_key_values={
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Status'): rdflib.term.Literal(u'OK'), 
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#OperationalStatus'): rdflib.term.Literal(u"type=<type 'list'>:[Uint16(cimtype='uint16', minvalue=0, maxvalue=65535, 2)]"), 
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#ElementName'): rdflib.term.Literal(u'Computer System'), 
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#isDefinedBy'): rdflib.term.Literal(u'WBEM'), 
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CreationClassName'): rdflib.term.Literal(u'PG_ComputerSystem'),
        # rdflib.term.URIRef(u'http://www.w3.org/1999/02/22-rdf-syntax-ns#type'): rdflib.term.URIRef(u'http://primhillcomputers.com/survol#CIM_ComputerSystem'), 
        # rdflib.term.URIRef(u'http://www.w3.org/2000/01/rdf-schema#seeAlso'): rdflib.term.Literal(u'WBEM'), 
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Caption'): rdflib.term.Literal(u'Computer System'), 
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#NameFormat'): rdflib.term.Literal(u'Other'), 
        # rdflib.term.URIRef(u'http://primhillcomputers.com/survol#Name'): rdflib.term.Literal(u'vps516494.ovh.net'), 

        iterator_objects = callback_object.CallbackSelect(grph, "CIM_ComputerSystem", "WBEM", filtered_where_key_values)
        list_objects = list(iterator_objects)

        currentIP = socket.gethostbyname(CurrentMachine)
        self.assertTrue(len(list_objects) == 1)
        for object_path, dict_key_values in list_objects:
            DEBUG(object_path)
            DEBUG(dict_key_values)

            self.assertTrue(GetElementAsString(dict_key_values, 'Status') == "OK")
            self.assertTrue(GetElementAsString(dict_key_values, 'ElementName') == "Computer System")

            # This tests the IP address because for example, CurrentMachine="vps516494.localdomain"
            # whereas WBEM returns "vps516494.ovh.net"
            wbemHostname = GetElementAsString(dict_key_values, 'Name')
            wbemIP = socket.gethostbyname(wbemHostname)
            self.assertTrue(wbemIP == currentIP)

    # Note: The class CIM_DataFile with the property Name triggers the exception message:
    # "CIMError: 7: CIM_ERR_NOT_SUPPORTED: No provider or repository defined for class"


    @unittest.skipIf(not is_linux_wbem(), "WBEM not usable here")
    def test_sparql_callback_associator(self):
        grph = lib_kbase.MakeGraph()
        iterator_objects = callback_object.CallbackAssociator(
                grph,
                result_class_name="CIM_Process",
                predicate_prefix="WBEM",
                associator_key_name="CIM_ComputerSystem",
                subject_path=r'//%s/root/cimv2:CIM_ComputerSystem.Name="%s"' % (CurrentMachine, CurrentMachine))
        for object_path, dict_key_values in iterator_objects:
            DEBUG("object_path=%s", object_path)
            DEBUG("dict_key_values=%s", istr(dict_key_values))

    @unittest.skipIf(not is_linux_wbem(), "WBEM not usable here")
    def test_sparql_callback_types(self):
        callback_object = lib_wbem.WbemSparqlCallbackApi()
        grph = lib_kbase.MakeGraph()
        iterator_types = callback_object.CallbackTypes(grph, "see_also", {})
        for object_path, dict_key_values in iterator_types:
            pass


if __name__ == '__main__':
    unittest.main()

