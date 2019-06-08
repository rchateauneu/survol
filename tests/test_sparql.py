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
import lib_util
import lib_properties
import lib_kbase

# "rchateau-hp"
CurrentMachine = socket.gethostname().lower()
try:
    CurrentUsername = os.environ["USERNAME"]
except KeyError:
    # This is for Linux.
    CurrentUsername = os.environ["USER"]

CurrentPid = os.getpid()
CurrentParentPid = psutil.Process().ppid()

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"

# Note: Cannot have backslashes in rdflib ??
dict_test_data = {
    "CIM_Process": [
        { "pid":123,"ppid":456,"user":"herself","runs":"firefox.exe"},
        { "pid":789,"ppid":123,"user":"himself","runs":"explorer.exe"},
    ],
    "CIM_DataFile": [
        { "owns":"herself","Name":"C:/Program Files (x86)/Internet Explorer/iexplore.exe"},
        { "owns":"someone","Name":"explorer.exe"},
    ],
    "CIM_Directory": [
        { "owns":"himself","Name":"C:/Program Files"},
        { "owns":"herself","Name":"C:/Program Files (x86)"},
    ],
    "Win32_UserAccount": [
        { "uid":111,"Name":"himself"},
        { "uid":222,"Name":"herself"},
    ],
}


# This returns an iterator on hard-coded objects, of a given class,
# which must match the input key-value pairs.
# Each object is modelled by a key-value dictionary.
def UnitTestExecuteQueryCallback(class_name, predicate_prefix, where_key_values):
    print("UnitTestExecuteQueryCallback class_name=",class_name," where_key_values=",where_key_values)

    def _check_key_val_included(one_data):
        try:
            for one_key,one_val in where_key_values.items():
                # Comparison in string.
                if str(one_val) != str(one_data[one_key]):
                    return False
            return True
        except KeyError:
            return False

    def _key_values_to_rdf(key_value_pair_dict):
        return {
            lib_properties.MakeProp(key):lib_util.NodeLiteral(value)
            for key,value in key_value_pair_dict.items()
        }

    # FIXME: CA NE RENTRE PAS DANS LE MODELE D'UNE FONCTION QUI RENVOIE DES OBJETS.
    # FIXME: Il faudrait une autre fonction pour traiter les ontologies.

    # Est ce qu i lpeut y avoir un melange entre les triples qui definissent des objets compatibles avec WMI,
    # et des triples "ontologiques" ?
    # Si WMI, on a besoin de la classe et des attributs, donc ca ne peut pas etre des variables:
    # Ce sont des traitements completement differents.
    # On pourrait separer les deux et interdire d avoir des variables communes.
    #
    # Ou alors, approche differente:
    # Il y a des callbacks qui recoivent des key-values et renvoient des objects.
    # On transforme immediatement ces objects en triples des la sortie de la callback.
    #
    # Des qu on appelle une callback, on transforme immediatement en triplets.
    # Et d ailleurs, les callbacks renvoient des triples et pas des objets.
    #
    #
    # En gros, on retire au fur et a mesure des triplets de la query et on remplace
    # par un triplestore qui grandit au fir et a mesure.


    # FIXME: AUTRE PROBLEME: ON NE SAIT PAS MODELISER LES ASSOCIATIONS.
    # FIXME: MAIS C EST INDISPENSABLE POUR LES JOINTURES.
    #SujetUrl association ObjectUrl
    #Avec WMI, si l object est un URL c est forcement un associator.

    test_key_value_pairs_list = dict_test_data[class_name]

    for one_key_value_pair_dict in test_key_value_pairs_list:
        if _check_key_val_included(one_key_value_pair_dict):
            yield ( lib_util.NodeUrl("hard_coded_path"), _key_values_to_rdf( one_key_value_pair_dict ) )

# The query function returns RDF nodes.
# Therefore, for tests, this is a helper function which returns dict of strings.
def QueryKeyValuePairs(sparql_query, execute_query_callback):
    def QueriesEntitiesToValuePairs(iter_entities_dicts):
        for one_entities_dict in iter_entities_dicts:

            one_entities_dict_qname = {}
            for variable_name, one_entity in one_entities_dict.items():
                print("one_entity=",one_entity)

                # Special attribute for debugging.
                dict_qname_value = { "__class__" : one_entity.m_entity_class_name }
                for key_node,val_node in one_entity.m_predicate_object_dict.items():
                    qname_key = lib_properties.PropToQName(key_node)
                    str_val = str(val_node)
                    dict_qname_value[qname_key] = str_val
                one_entities_dict_qname[variable_name] = dict_qname_value
            yield one_entities_dict_qname

    iter_entities_dicts = lib_sparql.QueryEntities(sparql_query, execute_query_callback)
    return QueriesEntitiesToValuePairs(iter_entities_dicts)


class SurvolSparqlTest(unittest.TestCase):

    @staticmethod
    def queries_test(test_pairs_array):
        for sparql_qry,expected_result in test_pairs_array:
            print(sparql_qry)

            dictEntitiesByVariable = lib_sparql._parse_query_to_key_value_pairs_dict(sparql_qry)
            print(expected_result)
            if(expected_result != dictEntitiesByVariable):
                print(dictEntitiesByVariable)
            assert(dictEntitiesByVariable==expected_result)

    # Generic parse capabilities
    def test_sparql_parse(self):
        query_result_pairs=[
            ("SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] . ?s2 ?p ?o .} ",{}),
            ("SELECT * WHERE { ?x  ?o1  ?name ; ?o2  ?mbox . } ",{}),
            #"SELECT * WHERE { ?x ?o1 ?name ; ?o2  ?a1 , ?a2 . }",{}),
            ("SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] .} ",{}),
            ("SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 . ?s2 ?p ?o .} ",{}),
            (
                """PREFIX foaf:  <http://xmlns.com/foaf/0.1/>
                SELECT ?name WHERE { ?person foaf:name ?name . }""",{'person': {u'foaf:name': lib_sparql.QueryVariable("name")}}
            ),
            ("""
                PREFIX  dc: <http://purl.org/dc/elements/1.1/>
                PREFIX  : <http://example.org/book/>
                SELECT  $title
                WHERE   { :book1  dc:title  $title }
                """,
            {}),
            ("""
                BASE    <http://example.org/book/>
                PREFIX  dc: <http://purl.org/dc/elements/1.1/>
                SELECT  $title
                WHERE   { <book1>  dc:title  ?title }
            """,
            {}),
            (
            """
                BASE    <http://example.org/book/>
                PREFIX  dcore:  <http://purl.org/dc/elements/1.1/>
                SELECT  ?title
                WHERE   { <book1> dcore:title ?title }
            """,
             {}),
            (
            """
                PREFIX foaf:   <http://xmlns.com/foaf/0.1/>
                SELECT ?mbox
                WHERE
                  { ?x foaf:name "Johnny Lee Outlaw" .
                    ?x foaf:mbox ?mbox }
            """,
             {'x': {u'foaf:name': 'Johnny Lee Outlaw', u'foaf:mbox': lib_sparql.QueryVariable("mbox")}}),
            (
            """
                PREFIX foaf:   <http://xmlns.com/foaf/0.1/>
                SELECT ?name ?mbox
                WHERE
                  { ?x foaf:name ?name .
                    ?x foaf:mbox ?mbox }
            """,
            {'x': {u'foaf:name': lib_sparql.QueryVariable("name"), u'foaf:mbox': lib_sparql.QueryVariable("mbox")}}),
            ("""
                SELECT ?p ?o
                {
                  <http://nasa.dataincubator.org/spacecraft/1968-089A> ?p ?o
                }
            """,
            {}),
            (
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
                {'item': {u'wdt:P2848': u'wd:Q1543615', u'wdt:P625': lib_sparql.QueryVariable("coord")}}),
            (
                """
                SELECT DISTINCT ?city ?cityLabel ?coor WHERE {
                    VALUES ?type { wd:Q3957 wd:Q515 wd:Q532 wd:Q486972 } .
                    ?city wdt:P31 wd:Q3957 ;
                          wdt:P625 ?coor .
                    FILTER NOT EXISTS {?article schema:about ?city } .
                    SERVICE wikibase:label { bd:serviceParam wikibase:language "en" } .
                }
                """,
                {'city': {u'wdt:P31': u'wd:Q3957',u'wdt:P625': lib_sparql.QueryVariable("coor")}}),
            (
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
                {'t': {u':saidBy': 'Bob', u'rdf:predicate': u'dc:title', u'rdf:subject': lib_sparql.QueryVariable("book"), u'rdf:object': lib_sparql.QueryVariable("title")}}
            ),
            (
                """
                select distinct ?Concept where {[] a ?Concept} LIMIT 100
                """,
                {}
            ),
            (
                """
                PREFIX go: <http://purl.org/obo/owl/GO#>
                PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
                PREFIX obo: <http://www.obofoundry.org/ro/ro.owl#>
                SELECT DISTINCT ?label ?process
                WHERE {
                  { ?process obo:part_of go:GO_0007165 } # integral to
                      UNION
                  { ?process rdfs:subClassOf go:GO_0007165 } # refinement of
                  ?process rdfs:label ?label
                }""",
                {'process': {u'obo:part_of': u'go:GO_0007165'}}
            ),
            ("""
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX type: <http://dbpedia.org/class/yago/>
            PREFIX prop: <http://dbpedia.org/property/>
            SELECT ?country_name ?population
            WHERE {
                ?country a type:LandlockedCountries ;
                         rdfs:label ?country_name ;
                         prop:populationEstimate ?population.
                FILTER (?population > 15000000) .
            }""",
            {'country': {'rdf:type': u'type:LandlockedCountries', u'rdfs:label': lib_sparql.QueryVariable("country_name"), u'prop:populationEstimate': lib_sparql.QueryVariable("population")}}
            ),
            ("""
            PREFIX type: <http://dbpedia.org/class/yago/>
            PREFIX prop: <http://dbpedia.org/property/>
            SELECT ?country_name ?population
            WHERE {
                ?country a type:LandlockedCountries ;
                         rdfs:label ?country_name ;
                         prop:populationEstimate ?population .
                FILTER (?population > 15000000 && langMatches(lang(?country_name), "EN")) .
            } ORDER BY DESC(?population)
            """,
            {'country': {u'rdfs:label': lib_sparql.QueryVariable("country_name"),
                         'rdf:type': u'type:LandlockedCountries', u'prop:populationEstimate': lib_sparql.QueryVariable("population")}}
            ),
            ("""
            PREFIX mo: <http://purl.org/ontology/mo/>
            PREFIX foaf:  <http://xmlns.com/foaf/0.1/>
            SELECT ?name ?img ?hp ?loc
            WHERE {
              ?a a mo:MusicArtist ;
                 foaf:name ?name .
              OPTIONAL { ?a foaf:img ?img }
              OPTIONAL { ?a foaf:homepage ?hp }
              OPTIONAL { ?a foaf:based_near ?loc }
            }
            """,
            {'a': {'rdf:type': u'mo:MusicArtist', u'foaf:name': lib_sparql.QueryVariable("name")}}
            ),
            ("""
            PREFIX go: <http://purl.org/obo/owl/GO#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX obo: <http://www.obofoundry.org/ro/ro.owl#>
            SELECT DISTINCT ?label ?process
            WHERE {
              { ?process obo:part_of go:GO_0007165 } # integral to
                  UNION
              { ?process rdfs:subClassOf go:GO_0007165 } # refinement of
              ?process rdfs:label ?label
            }
            """,
            {'process': {u'obo:part_of': u'go:GO_0007165'}}
            ),
            ("""
            PREFIX vCard: <http://www.w3.org/2001/vcard-rdf/3.0#>
            PREFIX foaf: <http://xmlns.com/foaf/0.1/>
            CONSTRUCT {
              ?X vCard:FN ?name .
              ?X vCard:URL ?url .
              ?X vCard:TITLE ?title .
            }FROM <http://www.w3.org/People/Berners-Lee/card>
            WHERE {
              OPTIONAL { ?X foaf:name ?name . FILTER isLiteral(?name) . }
              OPTIONAL { ?X foaf:homepage ?url . FILTER isURI(?url) . }
              OPTIONAL { ?X foaf:title ?title . FILTER isLiteral(?title) . }
            }
            """,
            {'X': {u'foaf:name': lib_sparql.QueryVariable("name")}}
            ),
            ("""
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
            PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
            PREFIX type: <http://dbpedia.org/class/yago/>
            PREFIX prop: <http://dbpedia.org/property/>
            SELECT ?lbl ?est
            WHERE {
              ?country rdfs:label ?lbl .
              FILTER(bif:contains(?lbl, "Republic")) .
              ?country a type:Country108544813 ;
                  prop:establishedDate ?est .
              FILTER(?est < "1920-01-01"^^xsd:date) .
            }
            """,
            {'country': {u'rdfs:label': lib_sparql.QueryVariable("lbl")}}
            ),
        ]
        self.queries_test(query_result_pairs)


    # This transforms a sparql query into a several nested loops fetching data from CIM classes.
    # The attributes are taken from the Sparql query without modification.
    # It is up to the execution, to check if these attributes are available.
    # This does not return the same results as a Spqrql query: It simply returns the set of objects
    # which match the query.
    # Another step is necessary to transform thesedata into the format of a Sparql output.
    # TODO: There should be a way to specify the associators or references explicitely,
    # TODO: in the SparQL query.
    def test_sparql_hardcoded(self):

        list_query_to_output_hardcoded =[
            (
            # The SPARQL keyword "a" is a shortcut for the common predicate rdf:type, giving the class of a resource.
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:pid    ?the_pid  .
              ?url_proc survol:ppid  456 .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """,
               [
                   {"url_proc":{'__class__': 'CIM_Process', 'runs': 'firefox.exe', 'ppid': '456', 'pid': '123', 'user': 'herself'},},
               ]
            ),
            (
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_owner
            WHERE
            { ?url_dir survol:Name "C:/Program Files" .
              ?url_dir rdf:type survol:CIM_Directory .
              ?url_dir survol:owns ?the_owner .
            }
            """,
               [
                   {'url_dir': {'__class__': 'CIM_Directory', 'Name': 'C:/Program Files', 'owns': 'himself'},}
               ]
            ),

            (
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_owner
            WHERE
            { ?url_file survol:Name "C:/Program Files (x86)/Internet Explorer/iexplore.exe"  .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_file survol:owns ?the_owner .
            }
            """,
               [
                   {"url_file": {'__class__': 'CIM_DataFile', 'Name': 'C:/Program Files (x86)/Internet Explorer/iexplore.exe', 'owns': 'herself'},}
               ]
            ),

            (
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_proc1 survol:runs  "firefox.exe" .
              ?url_proc1 rdf:type survol:CIM_Process .
              ?url_proc1 survol:pid    ?the_pid  .
              ?url_proc2 survol:ppid    ?the_pid  .
              ?url_proc2 rdf:type survol:CIM_Process .
            }
            """,
               [
                   {
                       "url_proc2":{'__class__': 'CIM_Process', 'runs': 'explorer.exe', 'ppid': '123', 'pid': '789', 'user': 'himself'},
                       "url_proc1":{'__class__': 'CIM_Process', 'runs': 'firefox.exe', 'ppid': '456', 'pid': '123', 'user': 'herself'},
                   }
               ]
            ),

            # TODO: The associators and references model is not very natural.
            # TODO: It is technically more complicated than a plain relational model,
            # TODO: plus one or two extra types, which are not portable between WMI and WBEM.
            # TODO: And it does not have any capability of SQL.
            # TODO: And it is very slow.

            (
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_proc survol:runs "firefox.exe" .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:user    ?the_username  .
              ?url_acct survol:Name    ?the_username  .
              ?url_acct rdf:type survol:Win32_UserAccount .
            }
            """,
               [
                   {
                       "url_proc":{'__class__': 'CIM_Process', 'runs': 'firefox.exe', 'ppid': '456', 'pid': '123', 'user': 'herself'},
                       "url_acct":{'__class__': 'Win32_UserAccount', 'Name': 'herself', 'uid': '222'},
                   }
               ]
            ),

            (
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_fil rdf:type survol:CIM_DataFile .
              ?url_fil survol:owns ?the_username  .
              ?url_proc survol:runs "firefox.exe" .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:user ?the_username  .
            }
            """,
               [
                   {
                       "url_proc":{'__class__': 'CIM_Process', 'runs': 'firefox.exe', 'ppid': '456', 'pid': '123', 'user': 'herself'},
                       "url_fil":{'__class__': 'CIM_DataFile', 'Name': 'C:/Program Files (x86)/Internet Explorer/iexplore.exe', 'owns': 'herself'},
                   }
               ]
            ),
            # (
            # """
            # SELECT DISTINCT ?a_type
            # WHERE {
            #     ?a_type rdf:type rdf:type .
            # }
            # """,
            #     [
            #         {"a_type":{'__class__': 'CIM_Directory', },},
            #         {"a_type":{'__class__': 'Win32_UserAccount', },},
            #         {"a_type":{'__class__': 'CIM_Process', },},
            #         {"a_type":{'__class__': 'CIM_DataFile', },},
            #     ]
            # ),
        ]

        for sparql_query,expected_results in list_query_to_output_hardcoded:
            print(sparql_query)

            itr_dict_objects = QueryKeyValuePairs(sparql_query, UnitTestExecuteQueryCallback)
            list_dict_objects = list(itr_dict_objects)
            #list_dict_objects = list(itr_dict_objects.m_predicate_object_dict)
            print("list_dict_objects=",list_dict_objects)

            print("expected_results=",expected_results)
            assert(list_dict_objects == expected_results)

    def test_sparql_survol_static(self):
        """
        Test the Sparql server which works on Survol data.
        The attributes in the SparQL query must match the ontology of the query callback function.
        """

        dict_query_to_output_survol =[
            [
            # This should select the parent process id
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            SELECT ?the_ppid
            WHERE
            { ?url_proc survol:Handle %d .
              ?url_proc survol:ppid ?the_ppid .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """ % CurrentPid,
               [
                   { "url_proc":{'ppid': str(CurrentParentPid), 'Handle': str(CurrentPid), 'user': CurrentUsername, '__class__': 'CIM_Process'}},
               ]
            ],
        ]

        for sparql_query, expected_results in dict_query_to_output_survol:
            print("===================================================")
            print(sparql_query)

            # TODO: Pass several callbacks, processed in a specific order ?
            itr_dict_objects = QueryKeyValuePairs(sparql_query, lib_sparql.SurvolExecuteQueryCallback)
            list_dict_objects = list(itr_dict_objects)

            print("list_dict_objects=",list_dict_objects)
            print("expected_results=",expected_results)
            assert(list_dict_objects == expected_results)

    def test_sparql_survol_nested(self):
        """
        Test the Sparql server which works on Survol data.
        The attributes in the SparQL query must match the ontology of the query callback function.
        """

        # It should return sibling processes (Same parent id) of the current process.
        nested_qry ="""
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            SELECT ?the_ppid
            WHERE
            {
              ?url_procA survol:Handle %d .
              ?url_procA survol:ppid ?the_ppid .
              ?url_procA rdf:type survol:CIM_Process .
              ?url_procB survol:Handle ?the_ppid .
              ?url_procB rdf:type survol:CIM_Process .
              ?url_procC survol:Handle %d .
              ?url_procC survol:ppid ?the_ppid .
              ?url_procC rdf:type survol:CIM_Process .
            }
            """ % (CurrentPid,CurrentPid)

        # TODO: Pass several callbacks, processed in a specific order ?
        itr_dict_objects = QueryKeyValuePairs(nested_qry, lib_sparql.SurvolExecuteQueryCallback)
        list_dict_objects = list(itr_dict_objects)

        print("list_dict_objects=",list_dict_objects)
        found = False
        for one_dict in list_dict_objects:
            procA = one_dict["url_procA"]
            procC = one_dict["url_procC"]
            if procA == procC:
                found = True
                break
        assert(found)

    def test_sparql_wmi(self):

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

        import lib_wmi

        for sparql_query, expected_results in dict_query_to_output_wmi:
            print("===================================================")
            print(sparql_query)

            # TODO: Pass several callbacks, processed in a specific order ?
            itr_dict_objects = QueryKeyValuePairs(sparql_query, lib_wmi.WmiExecuteQueryCallback)

            list_dict_objects = list(itr_dict_objects)

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


    def test_sparql_wmi_to_rdf(self):
        """This inserts the evaluation into a RDF triplestore. """

        sparql_query = """
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_dir rdf:type survol:CIM_DiskDrive .
            }
            """

        import lib_wmi

        print(sparql_query)

        # TODO: Pass several callbacks, processed in a specific order ?
        itr_dict_objects = lib_sparql.QueryEntities(sparql_query, lib_wmi.WmiExecuteQueryCallback)

        list_dict_objects = list(itr_dict_objects)

        grph = lib_kbase.MakeGraph()

        for one_dict_objects in list_dict_objects:
            for variable_name, key_value_nodes in one_dict_objects.items():
                # Only the properties of the ontology are used in the moniker
                # The moniker is built with a subset of properties, in a certain order.
                # In Survol's ontology, these properties are defined by each class'function EntityOntology()
                # These properties must be the same for all ontologies: WMI, WBEM and Survol,
                # otherwise objects could not be shared.
                wmiInstanceNode = key_value_nodes.m_subject_path

                for key_node,value_node in key_value_nodes.m_predicate_object_dict.items():
                    grph.add((wmiInstanceNode,key_node,value_node))



    def test_sparql_server_survol(self):
        """
        Test the Sparql server which works on Survol data.
        The attributes in the SparQL query must match the ontology of the query callback function.
        """
        array_survol_queries=[
            [
            """
            PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT ?the_pid
            WHERE
            { ?url_proc survol:Handle    ?the_ppid  .
              ?url_proc survol:ppid  %d .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """ % os.getpid(),
                "xxx"
            ],
        ]

        for sparql_query, expected_results in array_survol_queries:
            print("sparql_query=",sparql_query)

            url_sparql = RemoteTestAgent + "/survol/sparql.py?query=" + lib_util.urllib_quote(sparql_query)

            response = lib_util.survol_urlopen(url_sparql)
            data = response.read().decode("utf-8")

class SparqlServerWMITest(unittest.TestCase):
    """
    Test the Sparql server which works on Survol data.
    The attributes in the SparQL query must match the ontology of the query callback function.
    """

    @staticmethod
    def __load_wmi_query(sparql_query):
        print("sparql_query=",sparql_query)

        url_sparql = RemoteTestAgent + "/survol/sparql_wmi.py?query=" + lib_util.urllib_quote(sparql_query)

        response = lib_util.survol_urlopen(url_sparql)
        docXmlRdf = response.read().decode("utf-8")

        # Strip the header: "Content-Type: application/xml; charset=utf-8"
        # TODO: Why not stripping it in lib_client.
        splitXml = "".join(docXmlRdf.split("\n")[2:])

        print("docXmlRdf=",docXmlRdf)
        print("splitXml=",splitXml)

        # We could use lib_client GetTripleStore because we just need to deserialize XML into RDF.
        # On the other hand, this would imply that a SparQL endpoint works just like that, and this is not sure.
        grphKBase = lib_kbase.triplestore_from_rdf_xml(splitXml)
        return grphKBase

    def test_Win32_UserAccount(self):
        sparql_query="""
            PREFIX wmi:  <http://www.primhillcomputers.com/ontology/wmi#>
            PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
            SELECT *
            WHERE
            { ?url_user rdf:type survol:Win32_UserAccount .
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
        #foundPath = False
        #print("expectedPath=",expectedPath)
        for rdfSubject, rdfPredicate, rdfObject in grphKBase:
            print(rdfSubject, rdfPredicate, rdfObject)

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


# This works: gwmi -Query 'xxxxx'
# ASSOCIATORS OF {Win32_Process.Handle=1520}
# ASSOCIATORS OF {CIM_Process.Handle=1520}
# ASSOCIATORS OF {CIM_Process.Handle=1520} where classdefsonly
# ASSOCIATORS OF {CIM_Process.Handle=1520} where resultclass=CIM_DataFile

# Pour les associators, on a besoin des clefs qui designent exactement l'objet: Bref, son URL.

if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.


