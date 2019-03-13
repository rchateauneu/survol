
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

from __future__ import print_function
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
    print(parsed)
    print(parsed.__class__.__name__)

    def printelt(elt,level):
        #print("    ",elt)
        print("    "*level,elt.__class__.__name__)
        if elt.__class__.__name__ == "list":
            for elt2 in elt:
                print("    "*(level+1),"e=",elt2)
        elif elt.__class__.__name__ == "CompValue":
            for key2 in elt:
                val2 = elt[key2]
                # print("    "*(level+1),key2," ==> ",type(val2),":",dir(val2),":",val2)
                print("    "*(level+1),"k=",key2," ==> ",type(val2))
                printelt(val2,level+1)
        elif elt.__class__.__name__ == "plist":
            for elt2 in elt:
                #print("    "*(level+1),elt2)
                printelt(elt2,level+1)
        elif elt.__class__.__name__ == "ParseResults":
            for elt2 in elt.asList():
                print( ("    "*(level+1) ) + "E=",elt2)
        elif elt.__class__.__name__ == "Variable":
            print("    "*(level+1),"var=",elt)
        else:
            print("?? ",elt.__class__.__name__,dir(elt))


    for elt in parsed.asList():
        printelt(elt,1)
    # print(parsed)
    #print_recursive(parsed)
    # print( yaml.dump(parsed, default_flow_style=False) )


arr=[
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 . ?s2 ?p ?o .} ",
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] . ?s2 ?p ?o .} ",
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
# """
# @prefix foaf:    <http://xmlns.com/foaf/0.1/> .
# _:a  foaf:name   "Johnny Lee Outlaw" .
# _:a  foaf:mbox   <mailto:outlaw@example.com> .
# _:b  foaf:name   "A. N. Other" .
# _:b  foaf:mbox   <mailto:other@example.com> .
# """,
"""
PREFIX foaf:   <http://xmlns.com/foaf/0.1/>
SELECT ?mbox
WHERE
  { ?x foaf:name "Johnny Lee Outlaw" .
    ?x foaf:mbox ?mbox }
""",
# """
# @prefix foaf:  <http://xmlns.com/foaf/0.1/> .
# _:a  foaf:name   "Johnny Lee Outlaw" .
# _:a  foaf:mbox   <mailto:jlow@example.com> .
# _:b  foaf:name   "Peter Goodguy" .
# _:b  foaf:mbox   <mailto:peter@example.org> .
# """,
"""
PREFIX foaf:   <http://xmlns.com/foaf/0.1/>
SELECT ?name ?mbox
WHERE
  { ?x foaf:name ?name .
    ?x foaf:mbox ?mbox }
""",
# """
# @prefix foaf:  <http://xmlns.com/foaf/0.1/> .
# _:a  foaf:name   "Alice" .
# _:b  foaf:name   "Bob" .
# """,
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
"""
""",
"""
""",
"""
""",
]

for elt in arr:
    print("===================================================")
    t(elt)

print("===================================================")
