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

# This loads the module from the source, so no need to install it, and no need of virtualenv.
sys.path.insert(0,"../survol")

# This is what we want to test.
import lib_sparql
import lib_util
import lib_properties
import lib_kbase
import lib_sparql_callback_survol

from init import *

# TODO: This should be a parameter.
# It points to the Survol adhoc CGI server: "http://rchateau-hp:8000"
RemoteTestAgent = "http://" + CurrentMachine + ":8000"

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

class HardcodeSparqlCallbackApi:
    # This returns an iterator on hard-coded objects, of a given class,
    # which must match the input key-value pairs.
    # Each object is modelled by a key-value dictionary.
    def CallbackSelect(self, grph, class_name, predicate_prefix, where_key_values):
        # Note: Cannot have backslashes in rdflib ??
        WARNING("HardcodeCallbackSelect class_name=%s predicate_prefix=%s where_key_values=%s",
                class_name, predicate_prefix, where_key_values)

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
        test_key_value_pairs_list = hard_coded_data_select[class_name]

        for one_key_value_pair_dict in test_key_value_pairs_list:
            if _check_key_val_included(one_key_value_pair_dict):
                hardcoded_path_dict = one_key_value_pair_dict.copy()
                hardcoded_path_dict["__class_name__"] = class_name
                hardcoded_path_str = json.dumps(hardcoded_path_dict)

                rdf_key_values = _key_values_to_rdf( one_key_value_pair_dict )
                lib_util.PathAndKeyValuePairsToRdf(grph, hardcoded_path_str, rdf_key_values)
                yield ( hardcoded_path_str, rdf_key_values )


    # Return type similar to HardcodeCallbackSelect.
    # This simulates WQL associators.
    def CallbackAssociator(
        self,
        grph,
        result_class_name,
        predicate_prefix,
        associator_key_name,
        subject_path):

        # result_class_name = CIM_DataFile
        # associator_key_name = ppid
        # subject_path_node = {u'pid': 123, u'runs': u'firefox.exe', u'ppid': 456, u'__class_name__': u'CIM_Process', u'user': u'herself'}

        hardcoded_path_dict = json.loads(subject_path)
        WARNING("HardcodeCallbackAssociator result_class_name=%s associator_key_name=%s subject_path_node=%s",
              result_class_name,
              associator_key_name,
              hardcoded_path_dict)

        hard_coded_data_associator_keys = {
            'CIM_Process': ('pid',),
            'CIM_DataFile': ('Name',),
            'CIM_Directory': ('Name',),
        }

        hard_coded_data_associator = {
            'CIM_Process' : {
                (123,) : { 'ParentProcess' : { 'CIM_DataFile' : [{ "Name":"firefox.exe"}]} }
            },
            'CIM_Directory': {
                ("C:/Program Files (x86)",): {'ParentDirectory': {'CIM_Directory': [{"Name": "C:"}]},},
                ("C:/Program Files (x86)/Internet Explorer",): {'ParentDirectory': {'CIM_Directory': [{"Name": "C:/Program Files (x86)"}]}, },
                ("C:/Program Files",): {'ParentDirectory': {'CIM_Directory': [{"Name": "C:"}]}, },
            },
        }

        print("hardcoded_path_dict=",hardcoded_path_dict)
        class_name = hardcoded_path_dict['__class_name__']
        ontology_keys = hard_coded_data_associator_keys[class_name] # For example ("pid")
        key_tuple = tuple( [hardcoded_path_dict[object_key] for object_key in ontology_keys ]) # (123) which is the pid.
        all_associators = hard_coded_data_associator[class_name]
        all_associators_per_assoc_class = all_associators[key_tuple]
        objects_per_associator_class = all_associators_per_assoc_class[associator_key_name]
        objects_per_result_class = objects_per_associator_class[result_class_name]

        for one_object in objects_per_result_class:
            hardcoded_path_str = json.dumps(hardcoded_path_dict)

            lib_util.PathAndKeyValuePairsToRdf(grph, hardcoded_path_str, one_object)
            yield (hardcoded_path_str, one_object)

# The query function from lib_sparql module, returns RDF nodes.
# This is not very convenient to test.
# Therefore, for tests, this is a helper function which returns dict of strings,
# which are easier to compare.
def QueriesEntitiesToValuePairs(iter_entities_dicts):
    for one_entities_dict in iter_entities_dicts:

        one_entities_dict_qname = {}
        for variable_name, one_entity in one_entities_dict.items():
            # print("QueriesEntitiesToValuePairs one_entity=", one_entity)

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
    print("url_rdf=",url_rdf)

    response = lib_util.survol_urlopen(url_rdf)
    doc_xml_rdf = response.read().decode("utf-8")

    print("doc_xml_rdf=",doc_xml_rdf)

    # We could use lib_client GetTripleStore because we just need to deserialize XML into RDF.
    # On the other hand, this would imply that a SparQL endpoint works just like that, and this is not sure.
    grphKBase = lib_kbase.triplestore_from_rdf_xml(doc_xml_rdf)
    return grphKBase

################################################################################

class SparqlCallPortableTest(unittest.TestCase):

    @staticmethod
    def queries_test(test_pairs_array):
        for sparql_query, expected_result in test_pairs_array:
            print("sparql_query=",sparql_query)

            list_object_key_values = lib_sparql._parse_query_to_key_value_pairs_list(sparql_query)

            dictEntitiesDictsByVariable = {}
            # Transformed into dictionary to match the expected results.
            for one_object_key_value in list_object_key_values:
                key_value_pairs_dict = dict({key: value for key, value in one_object_key_value.m_raw_key_value_pairs})
                dictEntitiesDictsByVariable[one_object_key_value.m_object_variable_name] = key_value_pairs_dict

            print("expected_result=", expected_result)
            if expected_result != dictEntitiesDictsByVariable:
                print("dictEntitiesDictsByVariable=",dictEntitiesDictsByVariable)
            assert(dictEntitiesDictsByVariable==expected_result)

    # Generic parse capabilities
    def test_parse(self):
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

    # CONSTRUCT is an alternative SPARQL result clause to SELECT. Instead of returning a table of result values, CONSTRUCT returns an RDF graph.

    # DESCRIBE query result clause allows the server to return whatever RDF it wants that describes the given resource(s).

    def test_sparql_binding(self):
        """This lists the colums in the SELECT clause"""

        sparql_queries_binding = [
            ("select ?a ?b where { ?a a ?b . }", ['a', 'b']),
            ("""
            PREFIX foaf: <http://xmlns.com/foaf/0.1/>
            SELECT ?craft ?homepage
            {
              ?craft foaf:name "Apollo 7" .
              ?craft foaf:homepage ?homepage
            }""",['craft', 'homepage']),
            ("""
            SELECT DISTINCT ?concept
            WHERE {
                ?s a ?concept .
            } LIMIT 50
            """,['concept']),
        ]

        for sparql_query, expected_results in sparql_queries_binding:
            print("sparql_query=",sparql_query)
            row_header = lib_sparql.QueryHeader(sparql_query)
            print("row_header=",row_header)
            assert(row_header == expected_results)

    # This transforms a sparql query into a several nested loops fetching data from CIM classes.
    # The attributes are taken from the Sparql query without modification.
    # It is up to the execution, to check if these attributes are available.
    # This does not return the same results as a Spqrql query: It simply returns the set of objects
    # which match the query.
    # Another step is necessary to transform thesedata into the format of a Sparql output.
    # TODO: There should be a way to specify the associators or references explicitely,
    # TODO: in the SparQL query.
    def test_hardcoded_select(self):

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
        ]

        for sparql_query,expected_results in list_query_to_output_hardcoded:
            print(sparql_query)

            print("expected_results=",expected_results)
            list_dict_objects = QueryKeyValuePairs(sparql_query, HardcodeSparqlCallbackApi() )
            print("list_dict_objects=",list_dict_objects)

            assert(list_dict_objects == expected_results)


    def test_hardcoded_associators(self):

        list_associators_hardcoded =[
            ( """
            SELECT *
            WHERE
            {
              ?url_proc survol:pid 123 .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:ParentProcess ?url_file .
              ?url_file survol:Name "explorer.exe" .
              ?url_file rdf:type survol:CIM_DataFile .
            }
            """, [{'url_proc': {'runs': 'firefox.exe', 'ppid': '456', 'pid': '123', '__class__': 'CIM_Process','user': 'herself'},
                          'url_file': {'__class__': 'CIM_DataFile', 'Name': 'firefox.exe'}}]
            ),
            ("""
            SELECT *
            WHERE
            {
              ?url_file survol:Name "explorer.exe" .
              ?url_file rdf:type survol:CIM_DataFile .
              ?url_proc survol:pid 123 .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_proc survol:ParentProcess ?url_file .
            }
            """, [{
                'url_proc': {'runs': 'firefox.exe', 'ppid': '456', 'pid': '123', '__class__': 'CIM_Process', 'user': 'herself'},
                'url_file': {'__class__': 'CIM_DataFile', 'Name': 'firefox.exe'}}]
                ),
            ("""
            SELECT *
            WHERE
            {
              ?url_dirA survol:Name "C:/Program Files (x86)" .
              ?url_dirA rdf:type survol:CIM_Directory .
              ?url_dirB survol:ParentDirectory ?url_dirA .
              ?url_dirB rdf:type survol:CIM_Directory .
            }
            """, [
                {
                    'url_dirA': {'__class__': 'CIM_Directory', 'Name': 'C:'},
                    'url_dirB': {'owns': 'himself', '__class__': 'CIM_Directory', 'Name': 'C:/Program Files'}},
                {
                    'url_dirA': {'__class__': 'CIM_Directory', 'Name': 'C:'},
                    'url_dirB': {'owns': 'herself', '__class__': 'CIM_Directory', 'Name': 'C:/Program Files (x86)'}},
                {
                    'url_dirA': {'__class__': 'CIM_Directory', 'Name': 'C:/Program Files (x86)'},
                    'url_dirB': {'owns': 'herself', '__class__': 'CIM_Directory', 'Name': 'C:/Program Files (x86)/Internet Explorer'}}]
            ),
            ("""
            SELECT *
            WHERE
            {
              ?url_dirA rdf:type survol:CIM_Directory .
              ?url_dirB survol:Name "C:/Program Files (x86)/Internet Explorer" .
              ?url_dirB survol:ParentDirectory ?url_dirA .
              ?url_dirB rdf:type survol:CIM_Directory .
            }
            """, [
                {
                    'url_dirA': {'__class__': 'CIM_Directory', 'Name': 'C:/Program Files (x86)'},
                    'url_dirB': {'owns': 'herself', '__class__': 'CIM_Directory', 'Name': 'C:/Program Files (x86)/Internet Explorer'}}]
             ),
        ]

        for sparql_query,expected_results in list_associators_hardcoded:
            print(sparql_query)

            print("expected_results=",expected_results)
            list_dict_objects = QueryKeyValuePairs(sparql_query, HardcodeSparqlCallbackApi())
            print("list_dict_objects=",list_dict_objects)

            assert(list_dict_objects == expected_results)

    def test_survol_static(self):
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
              ?url_proc survol:parent_pid ?the_ppid .
              ?url_proc rdf:type survol:CIM_Process .
            }
            """ % CurrentPid,
               [
                   { "url_proc":{
                        'parent_pid': str(CurrentParentPid),
                        #'rdf-schema#isDefinedBy': 'CIM_Process:SelectFromWhere',
                        'Handle': str(CurrentPid),
                        'username': CurrentUsername,
                        'rdf-schema#isDefinedBy': 'survol',
                        'rdf-schema#seeAlso': 'survol',
                        '__class__': 'CIM_Process'}},
               ]
            ],
        ]

        for sparql_query, expected_results in dict_query_to_output_survol:
            print("===================================================")
            print(sparql_query)

            # TODO: Pass several callbacks, processed in a specific order ?
            list_dict_objects = QueryKeyValuePairs(
                sparql_query,
                lib_sparql_callback_survol.SurvolSparqlCallbackApi())

            print("list_dict_objects=",list_dict_objects)
            print("expected_results=",expected_results)
            assert(list_dict_objects == expected_results)

    def test_survol_nested(self):
        """
        Test the Sparql server which works on Survol data.
        The loop is done with the optional method SelectFromWhere, specific to each class.
        The attributes in the SparQL query must match the ontology of the query callback function.
        """

        # This returns the sibling processes (Same parent id) of the current process.
        nested_qry ="""
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

        # TODO: Pass several callbacks, processed in a specific order ?
        list_dict_objects = QueryKeyValuePairs(
            nested_qry,
            lib_sparql_callback_survol.SurvolSparqlCallbackApi())

        print("list_dict_objects=",list_dict_objects)
        found = False
        for one_dict in list_dict_objects:
            procA = one_dict["url_procA"]
            procC = one_dict["url_procC"]
            if procA == procC:
                found = True
                break
        assert(found)

    def test_survol_associators(self):
        """This returns the parent process using a specific script.
        """

        # output_entity.m_predicate_object_dict={
        # 'runs': 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=CIM_DataFile.Name=C%3A%2FProgram%20Files%2FJetBrains%2FPyCharm%20Community%20Edition%202019.1.3%2Fbin%2Ffsnotifier64.exe',
        # 'rdf-schema#label': 'fsnotifier64',
        # u'Handle': '7976',
        # 'Virtual_Memory_Size': '507904%20B',
        # 'pid': '7976',
        # '22-rdf-syntax-ns#type': 'http://www.primhillcomputers.com/survol#CIM_Process',
        # 'LMI_Account': 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=Win32_UserAccount.Name=rchateau,Domain=localhost',
        # 'command': 'C:%5CProgram%20Files%5CJetBrains%5CPyCharm%20Community%20Edition%202019.1.3%5Cbin%5Cfsnotifier64.exe'}
        sparql_query = """
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
            """ % CurrentPid

        list_dict_objects = QueryKeyValuePairs(
            sparql_query,
            lib_sparql_callback_survol.SurvolSparqlCallbackApi())

        # list_dict_objects= [
        # {'url_procB': {
        #   'runs': 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=CIM_DataFile.Name=C%3A%2FProgram%20Files%2FJetBrains%2FPyCharm%20Community%20Edition%202019.1.3%2Fbin%2Fpycharm64.exe',
        #   'Handle': '2544',
        #   'pid': '2544',
        #   '__class__': 'CIM_Process',
        #   'LMI_Account': 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=Win32_UserAccount.Name=rchateau,Domain=localhost',
        #   'command': 'C:%5CProgram%20Files%5CJetBrains%5CPyCharm%20Community%20Edition%202019.1.3%5Cbin%5Cpycharm64.exe',
        #   'ppid': 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=CIM_Process.Handle=13168',
        #   '22_rdf_syntax_ns#type': 'http://www.primhillcomputers.com/survol#CIM_Process'},
        # 'url_procA': {
        #   'rdf-schema#seeAlso': 'survol:CIM_Process/single_pidstree',
        #   'rdf-schema#isDefinedBy': 'survol:CIM_Process/single_pidstree',
        #   'Handle': '13168', '__class__': 'CIM_Process'}
        # }, ...
        print("list_dict_objects=",list_dict_objects)
        found = False
        for one_dict in list_dict_objects:
            procA = one_dict["url_procA"]
            procB = one_dict["url_procB"]
            WARNING("procA=%s",procA)
            WARNING("procB=%s",procB)

            procA_class = procA['__class__']
            procA_pid = procA['Handle']
            procA_url_str = 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=%s.Handle=%s' % (procA_class, procA_pid)

            try:
                parentB_url = procB['ppid'] # 'http://LOCALHOST:80/NotRunningAsCgi/entity.py?xid=CIM_Process.Handle=13168'
            except KeyError:
                continue

            WARNING("procA_url_str=%s",procA_url_str)
            WARNING("parentB_url=%s",parentB_url)
            if procA_url_str == parentB_url:
                found = True
                break
        assert(found)


class SparqlPreloadServerPortableTest(unittest.TestCase):
    """
    Test the Sparql server on all sources of data.
    """

    def test_server(self):
        return False


class SparqlPreloadServerSurvolPortableTest(unittest.TestCase):
    """
    Test the Sparql server which works on Survol data.
    """
    pass


prefix_to_callbacks = {
    "HardCoded": HardcodeSparqlCallbackApi(),
    "survol": lib_sparql_callback_survol.SurvolSparqlCallbackApi(),
}

unittestCallback = lib_sparql.SwitchCallbackApi(prefix_to_callbacks)

class SparqlSeeAlsoPortableTest(unittest.TestCase):
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
              ?url_fileB rdfs:seeAlso "WMI" .
              ?url_fileB rdf:type survol:CIM_DataFile .
            }""", ['xxx']
            ],

            # TODO: This is broken because arguments are mssing. It should display the error.
            ["""
            SELECT *
            WHERE
            { ?url_proc survol:Handle %d  .
              ?url_proc rdf:type survol:CIM_Process .
              ?url_file rdfs:seeAlso "WMI" .
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

            list_dict_objects = QuerySeeAlsoKeyValuePairs(None, sparql_query, unittestCallback)

            print("list_dict_objects=",list_dict_objects)
            print("GOLD=",one_expected_dict)
            assert(one_expected_dict in list_dict_objects)

if __name__ == '__main__':
    unittest.main()

# TODO: Test calls to <Any class>.AddInfo()
# TODO: When double-clicking any Python script, it should do something visible.

