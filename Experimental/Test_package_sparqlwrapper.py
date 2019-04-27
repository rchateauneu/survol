from __future__ import print_function

import SPARQLWrapper
import rdflib

# The goal is to understand the SPARQL HTTP protocol.
# It connects to Survol SPARQL server.

# query =
#     PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>
#     SELECT ?label
#     WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }
#

sparql = SPARQLWrapper.SPARQLWrapper("http://rchateau-hp:8000/survol/sparql.py")
sparql.setQuery("""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?label
    WHERE { <http://dbpedia.org/resource/Asturias> rdfs:label ?label }
""")

# JSON and JSONLD do not work.
sparql.setReturnFormat(SPARQLWrapper.XML)
sparql_qry = sparql.query()
print("sparql_qry=",str(sparql_qry))
results = sparql_qry.convert()
print("results=",results)

grph = rdflib.Graph()
grph.parse( data=results, format = "application/rdf+xml" )

print("Len grph=",len(grph))