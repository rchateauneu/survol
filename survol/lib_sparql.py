# This transforms a SPARQL query into a WMI/WBEM query.
# This is extremely restricted.

import sys
import rdflib.plugins.sparql.parser

import lib_util

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

# This returns a list of lists of tokens.
# These second-level lists of tokens are a SPARQL list of patterns,
# that is, patterns separated by a semi-colon,
# because they share the same subject, or commans if they share the subject and the predicate,
# ended by a dot. When returned, the list of patterns have a length multiple of three,
# because it is made of concatenated RDF triples.
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

# This groups tokens by sequence of three, to create triples.
# All SPARQL constraints are mixed together
def aggregate_triples(raw_trpl):
    resu = []
    curr_trip = []
    cnt_trip = 0
    DEBUG("Len raw_trpl=%s",len(raw_trpl))
    for block in raw_trpl:
        for elt in block:
            cnt_trip += 1
            curr_trip.append(elt)
            if cnt_trip == 3:
                resu.append(curr_trip)
                cnt_trip = 0
                curr_trip = []

    if cnt_trip:
        resu.append(curr_trip)
    DEBUG("Len resu=%s",len(resu))
    return resu


def pname_to_string(pname):
    # pname_pname_{'localname': u'pid', 'prefix': u'survol'}
    value_localname = pname['localname']
    try:
        value_prefix = pname['prefix']
    except KeyError:
        value_prefix = ""
    value_name = value_prefix + ":" + value_localname
    return value_name

def decode_parsed_subject(subj):
    # PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'pid', 'prefix': u'survol'}}]}]}
    if isinstance(subj,rdflib.term.Variable):
        return("TRPL_VARIABLE",str(subj))
        return
    if isinstance(subj,rdflib.term.Literal):
        # rdflib.term.Literal(u'123', datatype=rdflib.term.URIRef(u'http://www.w3.org/2001/XMLSchema#integer')
        return("TRPL_LITERAL",str(subj))
    if isinstance(subj,rdflib.term.BNode):
        # rdflib.term.BNode('N9b69940d021342f7b9dd341a53ea947b')
        return("TRPL_NODE",str(subj))
    if isinstance(subj,rdflib.term.URIRef):
        # rdflib.term.URIRef(u'http://nasa.dataincubator.org/spacecraft/1968-089A')
        return("TRPL_URIREF",str(subj))
    if isinstance(subj,rdflib.plugins.sparql.parserutils.CompValue):
        if 'string' in subj:
            # literal_literal_{'string': rdflib.term.Literal(u'CIM_Process')}
            litt_string = subj['string']
            # rdflib.term.Literal(u'CIM_Process')
            return("TRPL_LITERAL",str(litt_string))
        if 'localname' in subj:
            return("TRPL_VALUE_NAME",pname_to_string(subj))
    print("ERRSUBJsubj",subj)
    print("ERRSUBJsubj",type(subj))
    raise Exception("Cannot parse")

def decode_parsed_predicate(pred):
    # PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'pid', 'prefix': u'survol'}}]}]}
    if isinstance(pred,rdflib.plugins.sparql.parserutils.CompValue):
        try:
            one_part = pred['part']
        except KeyError:
            print("pred=",pred)
            raise
        if isinstance(one_part,rdflib.plugins.sparql.parserutils.plist):
            assert(len(one_part)==1)
            one_part_first = one_part[0]
            if isinstance(one_part_first,rdflib.plugins.sparql.parserutils.CompValue):
                one_part_part = one_part_first['part']
                if isinstance(one_part_part,rdflib.plugins.sparql.parserutils.plist):
                    assert(len(one_part_part)==1)
                    one_part_part_first = one_part_part[0]
                    if isinstance(one_part_part_first,rdflib.plugins.sparql.parserutils.CompValue):
                        one_part_part_first_part = one_part_part_first['part']
                        resu = pname_to_string(one_part_part_first_part)

                        return("TRPL_PREDICATE",resu)

    elif isinstance(pred,rdflib.term.Variable):
        # rdflib.term.Variable(u'p')
        return("TRPL_VARIABLE",str(pred))
    elif isinstance(pred,rdflib.term.BNode):
        return("TRPL_NODE",pred)
    else:
        print("ERREUR")

        print("***:",type(pred))
        print("***:",dir(pred))
        raise Exception("Cannot parse")

# Examples of input:
# ['s', 'p3', 'N739bb0cc49f94657a365f080994a0e8f']
# [
#   'person',
#   "PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'name', 'prefix': u'foaf'}}]}]}",
#   'name']
# [
#   'x',
#   "PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'name', 'prefix': u'foaf'}}]}]}",
#   "literal_literal_{'string': rdflib.term.Literal(u'Johnny Lee Outlaw')}"]
# [
#   'item',
#   "PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'P2848', 'prefix': u'wdt'}}]}]}",
#   "pname_pname_{'localname': u'Q1543615', 'prefix': u'wd'}"]
def decode_parsed_triple(one_trpl):
    s0 = decode_parsed_subject(one_trpl[0])
    s1 = decode_parsed_predicate(one_trpl[1])
    s2 = decode_parsed_subject(one_trpl[2])

    clean_trpl = [s0,s1,s2]
    return clean_trpl

def GenerateTriplesList(qry):
    parsed = rdflib.plugins.sparql.parser.parseQuery(qry)

    raw_trpl = get_triples(parsed)
    trpl_lst = aggregate_triples(raw_trpl)
    for one_trpl in trpl_lst:
        clean_trpl = decode_parsed_triple(one_trpl)
        yield clean_trpl

# This receives the list of triples of a SPARQL query.
# It returns a dictionary of variables with constant attributes.
# The plan is to implement a minimalistic SPARQL engine,
# over WMI or WBEM.
# This is very restricted, because it does not work if there are joins.
# Also, the CIM class of the object must be known.
def ExtractEntities(lst_triples):
    dictVariables = {}

    # Gathers attributes of objects.
    for one_triple in lst_triples:
        if one_triple[0][0] != "TRPL_VARIABLE":
            continue
        # The predicate type could be "TRPL_VARIABLE"
        if one_triple[1][0] != "TRPL_PREDICATE":
            continue
        # The object type could be "TRPL_VARIABLE"
        if one_triple[2][0] != "TRPL_LITERAL":
            continue

        variable_name = one_triple[0][1]
        try:
            variable_dict = dictVariables[variable_name]
        except KeyError:
            variable_dict = {}
            dictVariables[variable_name] = variable_dict
        variable_dict[one_triple[1][1]] = one_triple[2][1]

    return dictVariables

def ClauseToQuery(one_clause):
    return one_clause[0]

def OneEntityToQuery(variable_name,key_vals):
    # If the class is not defined, cannot query.
    # TODO: Consider base classes ??
    try:
        class_name = key_vals['rdf:type']
    except KeyError:
        return ""

    tests = ""
    delim = " WHERE "
    for key,val in key_vals.items():
        if key == 'rdf:type':
            continue
        clause = '%s = "%s"' % ( key, val )
        tests += delim + clause
        delim = " AND "

    return "select * from " + class_name + tests

def EntitiesToQuery(lstEntities):
    return ";".join( OneEntityToQuery(variable_name,key_vals) for variable_name, key_vals in lstEntities.items() )

# http://timgolden.me.uk/python/downloads/wmi-0.6b.py

# Quand on a un triplet de cette forme, trouver toutes les proprietes
# litterales relatives au sujet.
# Subj: ('VARIABLE=', 't')
# Pred: ('Predicate', u'rdf:type')
# Obj: ('litt_string', 'CIM_Process')# On peut alors en faire des requetes WMI ou WBEM, eventuellement.
#
# En theorie, c'est toujours possible mais probablement tres lent.
#
# Si on a les bons attributs, on peut executer le script principal dans survol.
