
# Many SPARQL examples.
# http://api.talis.com/stores/space/items/tutorial/spared.html?query=SELECT+%3Fp+%3Fo%0D%0A{+%0D%0A++%3Chttp%3A%2F%2Fnasa.dataincubator.org%2Fspacecraft%2F1968-089A%3E+%3Fp+%3Fo%0D%0A}
#
# This is equivalent to:
# SELECT ?p ?o
# {
#   <http://nasa.dataincubator.org/spacecraft/1968-089A> ?p ?o
# }
#
# Special characters encoded in hexadecimal.

import rdflib.plugins.sparql.parser
import pprint

import yaml

#dict_example = {'1': '1', '2': '2', '3': [1, 2, 3, 4, 5], '4': {'1': '1', '2': '2', '3': [1, 2, 3, 4, 5]}}
#dict_string = pformat(dict_example)
#formatted_code, _ = FormatCode(dict_string)
#print(formatted_code)
import sys

def print_recursive_OLD(data,level = 0):
    if isinstance(data,(list,tuple)):
        for elt in data:
            print_recursive_OLD(elt,level+1)
    elif isinstance(data,dict):
        for key in data:
            val = data[key]
            sys.stdout.write("    "*level)
            sys.stdout.write(key)
            print_recursive_OLD(val,level+1)
    else:
        sys.stdout.write("    "*level)
        sys.stdout.write(str(type(data)))
        sys.stdout.write(str(dir(data)))
        sys.stdout.write(data)
        sys.stdout.write("\n")

def print_recursive(data,level = 0):
    if isinstance(data,(list,tuple)):
        for elt in data:
            print_recursive(elt,level+1)
    elif isinstance(data,dict):
        for key in data:
            val = data[key]
            sys.stdout.write("    "*level)
            sys.stdout.write(key)
            print_recursive(val,level+1)
    else:
        try:
            sys.stdout.write("*****\n")
            for elt in data.items():
                print_recursive(elt,level+1)
        except AttributeError:
            sys.stdout.write("    "*level)
            sys.stdout.write(str(type(data)))
            sys.stdout.write(str(dir(data)))
            sys.stdout.write(data)
            sys.stdout.write("\n")



def t(q):
    print(q)
    parsed = rdflib.plugins.sparql.parser.parseQuery(q)
    pprint.pprint(parsed)
    print_recursive(parsed)
    # print( yaml.dump(parsed, default_flow_style=False) )


arr=[
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 . ?s2 ?p ?o .} ",
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] . ?s2 ?p ?o .} ",
"""PREFIX foaf:  <http://xmlns.com/foaf/0.1/>
SELECT ?name
WHERE {
    ?person foaf:name ?name .
}"""
        ]

for elt in arr:
    print("===================================================")
    t(elt)

print("===================================================")
