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
import sys

# This is not very elegant but does not matter for this kind of test.
sys.path.append("../survol")
import lib_sparql


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
# The SPARQL keyword a is a shortcut for the common predicate rdf:type, giving the class of a resource.
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?the_pid
WHERE
{ ?t survol:pid    ?the_pid  .
  ?t survol:ppid  123 .
  ?t rdf:type "CIM_Process" .
}
""",
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?the_pid
WHERE
{ ?t survol:name "C:/Users/Public"  .
  ?t rdf:type "CIM_Directory" .
}
""",
"""
PREFIX survol:  <http://www.primhillcomputers.com/ontology/survol#>
PREFIX rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?the_pid
WHERE
{ ?t survol:name "C:/Program Files (x86)/Internet Explorer/iexplore.exe"  .
  ?t rdf:type "CIM_FileName" .
}
""",
]

for qry in arr:
    print("===================================================")
    # parse_qry(elt)
    print(qry)
    lstTriples = list( lib_sparql.GenerateTriplesList(qry) )
    if False:
        for clean_trpl in lstTriples:
            print("--------------------")
            print("Subj:",clean_trpl[0])
            print("Pred:",clean_trpl[1])
            print("Obj:",clean_trpl[2])
        print("---------------------------------------------------")

    lstEntities = lib_sparql.ExtractEntities(lstTriples)
    print(lstEntities)
    wmi_qry = lib_sparql.EntitiesToQuery(lstEntities)
    print(wmi_qry)



print("===================================================")

