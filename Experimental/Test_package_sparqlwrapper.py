import SPARQLWrapper
from SPARQLWrapper import SPARQLWrapper, JSON

# The goal is to understand the SPARQL HTTP protocol.
# It connects to Survol SPARQL server.

# query =
#     PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>
#     SELECT ?label
#     WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }
#
# format = json
# results = json
# output = json

# sparql = SPARQLWrapper("http://dbpedia.org/sparql")
sparql = SPARQLWrapper("http://rchateau-hp:8000/survol/sparql.py")
sparql.setQuery("""
    PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
    SELECT ?label
    WHERE { <http://dbpedia.org/resource/Asturias> rdfs:label ?label }
""")
sparql.setReturnFormat(JSON)
sparql_qry = sparql.query()
print(sparql_qry)
results = sparql_qry.convert()
print(results)
for result in results["results"]["bindings"]:
    print('%s: %s' % (result["label"]["xml:lang"], result["label"]["value"]))