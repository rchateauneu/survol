#!/usr/bin/python

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

import cgitb
import cgi
import os
import sys
import unittest
import socket
import psutil

# This loads the module from the source, so no need to install it, and no need of virtualenv.
sys.path.insert(0,"../survol")

# This is what we want to test.
import lib_sparql
import lib_client
import lib_util

# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()
try:
    CurrentUsername = os.environ["USERNAME"]
except KeyError:
    # This is for Linux.
    CurrentUsername = os.environ["USER"]

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"

# Note: Cannot have backslashes in rdflib ??
# Returns one element, for testing.
dict_test_data = {
    "CIM_Process": [
        { "survol:pid":123,"survol:ppid":456,"survol:user":"herself","survol:runs":"firefox.exe"},
        { "survol:pid":789,"survol:ppid":123,"survol:user":"himself","survol:runs":"explorer.exe"},
    ],
    "CIM_DataFile": [
        { "survol:owns":"herself","survol:Name":"C:/Program Files (x86)/Internet Explorer/iexplore.exe"},
        { "survol:owns":"someone","survol:Name":"explorer.exe"},
    ],
    "CIM_Directory": [
        { "survol:owns":"himself","survol:Name":"C:/Program Files"},
        { "survol:owns":"herself","survol:Name":"C:/Program Files (x86)"},
    ],
    "Win32_UserAccount": [
        { "survol:uid":111,"survol:Name":"himself"},
        { "survol:uid":222,"survol:Name":"herself"},
    ],
}

# This returns an iterator on hard-coded objects, of a given class,
# which must match the input key-value pairs.
# Each object is modelled by a key-value dictionary.
def UnitTestExecuteQueryCallback(class_name, where_key_values):
    print("UnitTestExecuteQueryCallback class_name=",class_name," where_key_values=",where_key_values)

    test_key_value_pairs_list = dict_test_data[class_name]

    def CheckKeyValIncluded(one_data):
        try:
            for one_key in where_key_values:
                one_val = where_key_values[one_key]
                # Comparison in string.
                if str(one_val) != str(one_data[one_key]):
                    return False
            return True
        except KeyError:
            return False

    for one_key_value_pair_dict in test_key_value_pairs_list:
        if CheckKeyValIncluded(one_key_value_pair_dict):
            yield one_key_value_pair_dict


lib_sparql.ExecuteQueryCallback = UnitTestExecuteQueryCallback


class SurvolSparqlTest(unittest.TestCase):

    # Test parsing.
    def queries_test(self, arr):
        for qry in arr:
            print("===================================================")
            # parse_qry(elt)
            print(qry)

            dictEntitiesByVariable = lib_sparql.ParseQueryToEntities(qry)
            print(dictEntitiesByVariable)
            #wmi_qry = lib_sparql.EntitiesToQuery(lstEntities)
            #print(wmi_qry)

    # Generic parse capabilities
    def test_sparql_simple(self):
        arr=[
            "SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] . ?s2 ?p ?o .} ",
            "SELECT * WHERE { ?x  ?o1  ?name ; ?o2  ?mbox . } ",
            #"SELECT * WHERE { ?x ?o1 ?name ; ?o2  ?a1 , ?a2 . }",
            "SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] .} ",
            "SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 . ?s2 ?p ?o .} ",
            """PREFIX foaf:  <http://xmlns.com/foaf/0.1/>
            SELECT ?name WHERE { ?person foaf:name ?name . }""",
            """
            PREFIX  dc: <http://purl.org/dc/elements/1.1/>
            PREFIX  : <http://example.org/book/>
            SELECT  $title
            WHERE   { :book1  dc:title  $title }
            """,
            """
            BASE    <http://example.org/book/>
            PREFIX  dc: <http://purl.org/dc/elements/1.1/>
            SELECT  $title
            WHERE   { <book1>  dc:title  ?title }
            """,
            """
            BASE    <http://example.org/book/>
            PREFIX  dcore:  <http://purl.org/dc/elements/1.1/>
            SELECT  ?title
            WHERE   { <book1> dcore:title ?title }
            """,
            """
            PREFIX foaf:   <http://xmlns.com/foaf/0.1/>
            SELECT ?mbox
            WHERE
              { ?x foaf:name "Johnny Lee Outlaw" .
                ?x foaf:mbox ?mbox }
            """,
            """
            PREFIX foaf:   <http://xmlns.com/foaf/0.1/>
            SELECT ?name ?mbox
            WHERE
              { ?x foaf:name ?name .
                ?x foaf:mbox ?mbox }
            """,
            """
            SELECT ?p ?o
            {
              <http://nasa.dataincubator.org/spacecraft/1968-089A> ?p ?o
            }
            """,
            # https://www.wikidata.org/wiki/Wikidata:SPARQL_query_service/queries/examples
            # https://www.mediawiki.org/wiki/Wikibase/Indexing/RDF_Dump_Format#Prefixes_used

            # List of computer files formats
            """
            SELECT ?item ?itemLabel (SAMPLE(?coord) AS ?coord)
            WHERE {
                ?item wdt:P2848 wd:Q1543615 ;  # wi-fi gratis
                      wdt:P625 ?coord .
                SERVICE wikibase:label { bd:serviceParam wikibase:language "[AUTO_LANGUAGE],en" }
            } GROUP BY ?item ?itemLabel
            """,
            """
            SELECT DISTINCT ?city ?cityLabel ?coor WHERE {
                VALUES ?type { wd:Q3957 wd:Q515 wd:Q532 wd:Q486972 } .
                ?city wdt:P31 wd:Q3957 ;
                      wdt:P625 ?coor .
                FILTER NOT EXISTS {?article schema:about ?city } .
                SERVICE wikibase:label { bd:serviceParam wikibase:language "en" } .
            }
            """,
            """
            PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            PREFIX dc:   <http://purl.org/dc/elements/1.1/>
            PREFIX :     <http://example/ns#>
            SELECT ?book ?title
            WHERE
            { ?t rdf:subject    ?book  .
              ?t rdf:predicate  dc:title .
              ?t rdf:object     ?title .
              ?t :saidBy        "Bob" .
            }
            """,
        ]
        self.queries_test(arr)

    # More complex queries. Only the where clause is relevant
    def test_sparql_general(self):
        arr=[
            """
            select distinct ?Concept where {[] a ?Concept} LIMIT 100
            """,
        ]
        self.queries_test(arr)


    # This transforms a sparql query into a several nested loops fetching data from CIM classes.
    # The attributes are taken from the Sparql query without modification.
    # It is up to the execution, to check if these attributes are available.
    # This does not return the same results as a Spqrql query: It simply returns the set of objects
    # which match the query.
    # Another step is necessary to transform thesedata into the format of a Sparql output.
    # TODO: There should be a way to specify the associators or references explicitely,
    # TODO: in the SparQL query.
    def test_sparql_query_objects_hardcoded(self):

        dict_query_to_output_hardcoded =[
            [
            # The SPARQL keyword "a" is a shortcut for the common predicate rdf:type, giving the class of a resource.
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:pid    ?the_pid  .
              ?url_proc survol:ppid  456 .
              ?url_proc rdf:type "CIM_Process" .
            }
            """,
               [
                   ('CIM_Process?survol:runs=firefox.exe&survol:pid=123&survol:ppid=456&survol:user=herself',),
               ]
            ],

            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_owner
            WHERE
            { ?url_dir survol:Name "C:/Program Files" .
              ?url_dir rdf:type "CIM_Directory" .
              ?url_dir survol:owns ?the_owner .
            }
            """,
               [
                   ('CIM_Directory?survol:owns=himself&survol:Name=C:/Program Files',)
               ]
            ],

            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_owner
            WHERE
            { ?url_file survol:Name "C:/Program Files (x86)/Internet Explorer/iexplore.exe"  .
              ?url_file rdf:type "CIM_DataFile" .
              ?url_file survol:owns ?the_owner .
            }
            """,
               [
                   ('CIM_DataFile?survol:owns=herself&survol:Name=C:/Program Files (x86)/Internet Explorer/iexplore.exe',)
               ]
            ],

            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_proc1 survol:runs  "firefox.exe" .
              ?url_proc1 rdf:type "CIM_Process" .
              ?url_proc1 survol:pid    ?the_pid  .
              ?url_proc2 survol:ppid    ?the_pid  .
              ?url_proc2 rdf:type "CIM_Process" .
            }
            """,
               [
                   (
                       'CIM_Process?survol:runs=explorer.exe&survol:pid=789&survol:ppid=123&survol:user=himself',
                       'CIM_Process?survol:runs=firefox.exe&survol:pid=123&survol:ppid=456&survol:user=herself',
                   )
               ]
            ],

            # TODO: The associators and references model is not very natural.
            # TODO: It is technically more complicated than a plain relational model,
            # TODO: plus one or two extra types, which are not portable between WMI and WBEM.
            # TODO: And it does not have any capability of SQL.
            # TODO: And it is very slow.

            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_proc survol:runs "firefox.exe" .
              ?url_proc rdf:type "CIM_Process" .
              ?url_proc survol:user    ?the_username  .
              ?url_acct survol:Name    ?the_username  .
              ?url_acct rdf:type "Win32_UserAccount" .
            }
            """,
               [
                   (
                       'CIM_Process?survol:runs=firefox.exe&survol:pid=123&survol:ppid=456&survol:user=herself',
                       'Win32_UserAccount?survol:uid=222&survol:Name=herself',
                   )
               ]
            ],

            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_fil rdf:type "CIM_DataFile" .
              ?url_fil survol:owns ?the_username  .
              ?url_proc survol:runs "firefox.exe" .
              ?url_proc rdf:type "CIM_Process" .
              ?url_proc survol:user ?the_username  .
            }
            """,
               [
                   (
                       'CIM_Process?survol:runs=firefox.exe&survol:pid=123&survol:ppid=456&survol:user=herself',
                       'CIM_DataFile?survol:owns=herself&survol:Name=C:/Program Files (x86)/Internet Explorer/iexplore.exe',
                   )
               ]
            ],
        ]

        for qry_data in dict_query_to_output_hardcoded:
            print("===================================================")
            # parse_qry(elt)
            qry = qry_data[0]
            expected_results = qry_data[1]
            print(qry)

            dictEntitiesByVariable = lib_sparql.ParseQueryToEntities(qry)

            print(dictEntitiesByVariable)
            print("***************************************************")
            itr_tuple_objects = lib_sparql.QueryEntities(dictEntitiesByVariable, UnitTestExecuteQueryCallback)

            # This moniker exists just for testing. However, the result is similar to a RDF Url.
            def ObjectsToSparqlResults(list_objects):
                for curr_input_entity in list_objects:
                    entity_moniker = curr_input_entity.m_class_name + "?" + "&".join( [ "%s=%s" % kv for kv in curr_input_entity.m_key_values.items() ] )
                    yield entity_moniker

            list_tuple_objects = list(itr_tuple_objects)
            list_results = []
            for one_objects_tuple in list_tuple_objects:
                list_results.append( tuple(ObjectsToSparqlResults(one_objects_tuple)) )

            print("###################################################")
            print("list_results=",list_results)
            print("expected_results=",expected_results)
            assert(list_results == expected_results)

            print("+++++++++++++++++++++++++++++++++++++++++++++++++++")


    def test_sparql_query_objects_survol(self):
        """
        Test the Sparql server which works on Survol data.
        The attributes in the SparQL query must match the ontology of the query callback function.
        """

        curr_pid = os.getpid()
        curr_parent_pid = psutil.Process().ppid()

        dict_query_to_output_survol =[
            [
            # This should select the parent process id
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:Handle %d .
              ?url_proc survol:ppid ?the_pid .
              ?url_proc rdf:type "CIM_Process" .
            }
            """ % curr_pid,
               [
                   ('CIM_Process?survol:ppid=%d&survol:Handle=%d&survol:user=%s' % (curr_parent_pid,curr_pid,CurrentUsername),),
               ]
            ],
        ]

        for qry_data in dict_query_to_output_survol:
            print("===================================================")
            # parse_qry(elt)
            qry = qry_data[0]
            expected_results = qry_data[1]
            print(qry)

            dictEntitiesByVariable = lib_sparql.ParseQueryToEntities(qry)

            print(dictEntitiesByVariable)
            print("***************************************************")
            # TODO: Pass several callbacks, processed in a specific order ?
            itr_tuple_objects = lib_sparql.QueryEntities(dictEntitiesByVariable, lib_sparql.SurvolExecuteQueryCallback)

            # This moniker exists just for testing. However, the result is similar to a RDF Url.
            def ObjectsToSparqlResults(list_objects):
                for curr_input_entity in list_objects:
                    entity_moniker = curr_input_entity.m_class_name + "?" + "&".join( [ "%s=%s" % kv for kv in curr_input_entity.m_key_values.items() ] )
                    yield entity_moniker

            list_tuple_objects = list(itr_tuple_objects)
            list_results = []
            for one_objects_tuple in list_tuple_objects:
                list_results.append( tuple(ObjectsToSparqlResults(one_objects_tuple)) )

            print("###################################################")
            print("list_results=",list_results)
            print("expected_results=",expected_results)
            assert(list_results == expected_results)

            print("+++++++++++++++++++++++++++++++++++++++++++++++++++")

    def test_sparql_server_survol(self):
        """
        Test the Sparql server which works on Survol data.
        The attributes in the SparQL query must match the ontology of the query callback function.
        """
        arr_survol_queries=[
            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:Handle    ?the_ppid  .
              ?url_proc survol:ppid  %d .
              ?url_proc rdf:type "CIM_Process" .
            }
            """ % os.getpid(),
                "xxx"
            ],
        ]


        for qry_data in arr_survol_queries:
            print("===================================================")
            # parse_qry(elt)
            qry_sparql = qry_data[0]
            expected_results = qry_data[1]
            print("qry_sparql=",qry_sparql)

            url_sparql = RemoteTestAgent + "/survol/sparql.py?query=" + lib_util.urllib_quote(qry_sparql)
            print("url_sparql=",url_sparql)

            response = lib_util.survol_urlopen(url_sparql)
            data = response.read().decode("utf-8")
            print("data=",data)



if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.


