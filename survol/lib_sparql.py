import sys
import rdflib.plugins.sparql.parser

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
    print("----------------------------")
    resu = []
    curr_trip = []
    cnt_trip = 0
    print("Len raw_trpl=",len(raw_trpl))
    for block in raw_trpl:
        for elt in block:
            #print(elt,type(elt))
            cnt_trip += 1
            # curr_trip.append(str(elt))
            curr_trip.append(elt)
            if cnt_trip == 3:
                resu.append(curr_trip)
                cnt_trip = 0
                curr_trip = []

    if cnt_trip:
        resu.append(curr_trip)
    print("Len resu=",len(resu))
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

def process_subject(subj):
    # PathAlternative_PathAlternative_{'part': [PathSequence_{'part': [PathElt_{'part': pname_{'localname': u'pid', 'prefix': u'survol'}}]}]}
    if isinstance(subj,rdflib.term.Variable):
        return("VARIABLE=",str(subj))
        return
    if isinstance(subj,rdflib.term.Literal):
        # rdflib.term.Literal(u'123', datatype=rdflib.term.URIRef(u'http://www.w3.org/2001/XMLSchema#integer')
        return("Literal=",str(subj))
    if isinstance(subj,rdflib.term.BNode):
        # rdflib.term.BNode('N9b69940d021342f7b9dd341a53ea947b')
        return("NODE=",str(subj))
    if isinstance(subj,rdflib.term.URIRef):
        # rdflib.term.URIRef(u'http://nasa.dataincubator.org/spacecraft/1968-089A')
        return("URIRef=",str(subj))
    if isinstance(subj,rdflib.plugins.sparql.parserutils.CompValue):
        if 'string' in subj:
            # literal_literal_{'string': rdflib.term.Literal(u'CIM_Process')}
            litt_string = subj['string']
            # rdflib.term.Literal(u'CIM_Process')
            return("litt_string",str(litt_string))
        if 'localname' in subj:
            return("value_name",pname_to_string(subj))
    print("ERRSUBJsubj=",subj)
    print("ERRSUBJsubj=",type(subj))
    raise Exception("Cannot parse")

def process_predicate(pred):
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

                        return("Predicate",resu)

    elif isinstance(pred,rdflib.term.Variable):
        # rdflib.term.Variable(u'p')
        return("VARIABLE",str(pred))
    elif isinstance(pred,rdflib.term.BNode):
        return("NODE",pred)
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
def prepare_triple(one_trpl):
    s0 = process_subject(one_trpl[0])
    s1 = process_predicate(one_trpl[1])
    s2 = process_subject(one_trpl[2])

    #print(one_trpl[1],type(one_trpl[1]))
    clean_trpl = [s0,s1,s2]
    return clean_trpl

def ProcessQuery(qry):
    parsed = rdflib.plugins.sparql.parser.parseQuery(qry)

    raw_trpl = get_triples(parsed)
    trpl_lst = aggregate_triples(raw_trpl)
    for one_trpl in trpl_lst:
        clean_trpl = prepare_triple(one_trpl)
        print("--------------------")
        print("Subj:",clean_trpl[0])
        print("Pred:",clean_trpl[1])
        print("Obj:",clean_trpl[2])

