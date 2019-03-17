import SPARQLWrapper
from SPARQLWrapper import SPARQLWrapper, JSON

# The goal is to understand the SPARQL HTTP protocol.

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
results = sparql.query().convert()

for result in results["results"]["bindings"]:
    print('%s: %s' % (result["label"]["xml:lang"], result["label"]["value"]))