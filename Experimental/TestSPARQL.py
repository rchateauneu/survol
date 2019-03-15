
# Many SPARQL examples.
# http://api.talis.com/stores/space/items/tutorial/spared.html?query=SELECT+%3Fp+%3Fo%0D%0A{+%0D%0A++%3Chttp%3A%2F%2Fnasa.dataincubator.org%2Fspacecraft%2F1968-089A%3E+%3Fp+%3Fo%0D%0A}
#
# This is equivalent to:
#
# Special characters encoded in hexadecimal.

from __future__ import print_function
import sys
import rdflib.plugins.sparql.parser

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


# This works, but we are only interested by triples.
def print_simple(arg_elt,level=1):
    if arg_elt.__class__.__name__ == "list":
        print("    "*level,arg_elt.__class__.__name__)
        for elt2 in arg_elt:
            print("    "*(level+1),"L=",elt2,type(elt2))
    elif arg_elt.__class__.__name__ == "CompValue":
        print("    "*level,arg_elt.__class__.__name__)
        for key2 in arg_elt:
            val2 = arg_elt[key2]
            print("    "*(level+1),"Key=",key2," ==> ",type(val2))
            print_simple(val2,level+2)
    elif arg_elt.__class__.__name__ == "plist":
        print("    "*level,arg_elt.__class__.__name__)
        for elt2 in arg_elt:
            print_simple(elt2,level+1)
    elif arg_elt.__class__.__name__ == "ParseResults":
        print("    "*level,arg_elt.__class__.__name__)
        for elt2 in arg_elt.asList():
            print( ("    "*(level+1) )," ==>",type(elt2))
            print_simple(elt2,level+1)
    elif arg_elt.__class__.__name__ == "Variable":
        print("    "*level,"Variable=",arg_elt)
    elif arg_elt.__class__.__name__ == "URIRef":
        print("    "*level,"URIRef=",arg_elt)
    elif arg_elt.__class__.__name__ == "Literal":
        print("    "*level,"Literal=",arg_elt)
    elif arg_elt.__class__.__name__ == "unicode":
        print("    "*level,"unicode=",arg_elt)
    elif arg_elt.__class__.__name__ == "BNode":
        print("    "*level,"BNode=",arg_elt)
    else:
        print("    "*level,arg_elt.__class__.__name__)
        print("    "*level,"??? ",arg_elt.__class__.__name__,dir(arg_elt))


def get_triples(arg_elt):
    if arg_elt.__class__.__name__ == "CompValue":
        for key2 in arg_elt:
            val2 = arg_elt[key2]
            if key2 == "triples":
                return val2
            res = get_triples(val2)
            if res:
                return res
    elif arg_elt.__class__.__name__ in ["ParseResults","plist"]:
        for elt2 in arg_elt:
            res = get_triples(elt2)
            if res:
                return res
    return None


def aggregate_triples(raw_trpl):
    print("----------------------------")
    resu = []
    curr_trip = []
    cnt_trip = 0
    for block in raw_trpl:
        for elt in block:
            #print(elt,type(elt))
            cnt_trip += 1
            curr_trip.append(str(elt))
            if cnt_trip == 3:
                resu.append(curr_trip)
                cnt_trip = 0
                curr_trip = []

    if cnt_trip:
        resu.append(curr_trip)

    print("+++++++++++++++++++++++++++++")
    return resu


arr=[
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
SELECT ?p ?o
{
  <http://nasa.dataincubator.org/spacecraft/1968-089A> ?p ?o
}
""",
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] . ?s2 ?p ?o .} ",

# { x o1 name. x o2 mbox }
"SELECT * WHERE { ?x  ?o1  ?name ; ?o2  ?mbox . } ",

# { x o1 name. x o2 a1. x o2 a2 }
"SELECT * WHERE { ?x ?o1 ?name ; ?o2  ?a1 , ?a2 . }",

# s p o. s p o2. o p3 p3.
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p3 ?o3 .} ",

# s p o. s p o2. o p3 p3. o p4 o4
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p3 ?o3 ; ?p4 ?o4 .} ",

# x p1 o1. x p2 o2. x p3 o3.
"SELECT * WHERE { ?x  ?p1  ?o1 ; ?p2  ?o2 ; ?p3 ?o3 . } ",

# s p3 XXX. XXX p o.
"SELECT * WHERE { ?s ?p3 [ ?p ?o ]. }",

# ?s ?p ?o ; p3 XXX. XXX p4 o4.
# s p o. s p3 XXX. XXX p4 o4.
"SELECT * WHERE { ?s ?p ?o; ?p3 [ ?p4 ?o4 ] .} ",

# s p o. s p o2. o p3 XXX. XXX p4 o4.
"SELECT * WHERE { ?s ?p ?o, ?o2; ?p3 [ ?p4 ?o4 ] .} ",

# s p o. s p o2. s p o3. s p4 o4
"SELECT * WHERE { ?s ?p ?o, ?o2, ?o3 ; ?p4 ?o4 .} ",

# s p o. s p o2; ?p2 ?o3 ; ?p3 [ ?p ?o ] .
# s p o. s p o2. s ?p2 ?o3 ; ?p3 [ ?p ?o ] .
# s p o. s p o2. s ?p2 ?o3 ; ?p3 XX. XX  ?p ?o .
# s p o. s p o2. s ?p2 ?o3. s ?p3 XX. XX  ?p ?o .
# s p o. s p o2. s p2 o3. s p3 XX. XX p o.
"SELECT * WHERE { ?s ?p ?o, ?o2 ; ?p2 ?o3 ; ?p3 [ ?p ?o ] .} ",
]


def ProcessQuery(qry):
    print("===================================================")
    # parse_qry(elt)
    print(qry)
    parsed = rdflib.plugins.sparql.parser.parseQuery(qry)
    #print(parsed)
    #print(parsed.__class__.__name__)

    #print_simple(parsed)
    raw_trpl = get_triples(parsed)
    #print_simple(raw_trpl)
    trpl_lst = aggregate_triples(raw_trpl)
    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    for trpl in trpl_lst:
        print(trpl)


for qry in arr:
    ProcessQuery(qry)

print("===================================================")
