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
import rdflib

from init import *

update_test_path()

import lib_sparql
import lib_util
import lib_properties
import lib_sparql_custom_evals

################################################################################

class CUSTOM_EVALS_SeeAlso_Base_Test(unittest.TestCase):

    def setUp(self):
        # add function directly, normally we would use setuptools and entry_points
        rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function_see_also'] = lib_sparql_custom_evals.custom_eval_function_see_also

    def tearDown(self):
        if 'custom_eval_function_see_also' in rdflib.plugins.sparql.CUSTOM_EVALS:
            del rdflib.plugins.sparql.CUSTOM_EVALS['custom_eval_function_see_also']

################################################################################

class SparqlSeeAlsoPortableTest(unittest.TestCase):
    @staticmethod
    def compare_list_queries(array_survol_queries):
        for sparql_query, one_expected_dict in array_survol_queries:
            print("sparql_query=",sparql_query)

            list_dict_objects = QuerySeeAlsoKeyValuePairs(None, sparql_query)

            # The expected object must be a subset of one of the returned objects.
            #print("list_dict_objects=",list_dict_objects)
            #print("GOLD=",one_expected_dict)

            expected_keys = one_expected_dict.keys()
            found = False
            for one_dict_objects in list_dict_objects:
                actual_keys = one_dict_objects.keys()
                assert actual_keys == expected_keys
                print("TEST=",one_dict_objects)

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

    @unittest.skipIf( True, "SPARQL special cases not implemented.")
    def test_see_also_special(self):
        """Special Survol seeAlso pathes"""
        CurrentFile = __file__.replace("\\","/")
        array_survol_queries=[
            # TODO: This generates all allowed scripts.
            ["""
                SELECT *
                WHERE
                { ?url_proc rdf:type survol:CIM_DataFile .
                  ?url_proc rdfs:seeAlso ?script .
                }
                """,
                ['url_proc'],
            ],

            # This just loads the content of one script.
            ["""
                SELECT ?url_dummy
                WHERE
                { ?url_dummy rdfs:seeAlso "survol:enumerate_python_package" .
                }
                """,
                ['url_dummy'],
            ],

            ["""
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_proc survol:Handle %d  .
            ?url_proc rdf:type survol:CIM_Process .
            ?url_proc rdfs:seeAlso "survol:CIM_Process" .
            }
            """ % CurrentPid,
             ['url_proc'],
             ],

             ["""
             PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
             PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
             SELECT *
             WHERE
             { ?url_proc survol:Handle %d  .
               ?url_proc rdf:type survol:CIM_Process .
               ?url_proc rdfs:seeAlso "survol:CIM_Process/*" .
             }
             """ % CurrentPid,
             {'url_proc': {'Handle': str(CurrentPid), '__class__': 'CIM_Process'}},
             ],

             ["""
             PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
             PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
             SELECT *
             WHERE
             { ?url_proc survol:Name "/usr/lib/systemd/systemd-journald" .
               ?url_proc rdf:type survol:CIM_DataFile .
               ?url_proc rdfs:seeAlso <http://vps516494.ovh.net/Survol/survol/sources_types/CIM_DataFile/mapping_processes.py?xid=CIM_DataFile.Name%3D%2Fusr%2Flib%2Fsystemd%2Fsystemd-journald&mode=rdf> .
             }
             """,
             None,
             ],

            # If WMI is not used and not SelectFromWhere method for this class,
            # this just uses the key-value pair.
            ["""
            SELECT *
            WHERE
            { ?url_fileA survol:Name "C:/Windows"  .
              ?url_fileA rdf:type survol:CIM_Directory .
              ?url_fileA survol:CIM_DirectoryContainsFile ?url_fileB  .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""", ['xxx']
            ],

            # TODO: This is broken because arguments are mssing. It should display the error.
            ["""
            SELECT *
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file rdfs:seeAlso "survol:CIM_DataFile/python_properties" .
              ?url_file survol:CIM_ProcessExecutable ?url_proc  .
            }
            """ % CurrentPid,
            ['url_proc', 'url_file'],
            ],

            ["""
            SELECT *
            WHERE
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file rdfs:seeAlso "survol:does_not_exist" .
            }
            """,
             ['url_proc', 'url_file'],
             ],
        ]

        for sparql_query, one_expected_dict in array_survol_queries:
            print("sparql_query=",sparql_query)

            list_dict_objects = QuerySeeAlsoKeyValuePairs(None, sparql_query)

            #print("list_dict_objects=",list_dict_objects)
            #print("GOLD=",one_expected_dict)
            assert(one_expected_dict in list_dict_objects)

if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

