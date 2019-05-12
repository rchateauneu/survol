# This transforms a SPARQL query into a WMI/WBEM query.
# This is extremely restricted.

import sys
import rdflib.plugins.sparql.parser

import lib_util

# QUERY_STRING="query=%0A++++PREFIX+rdfs%3A+%3Chttp%3A/www.w3.org/2000/01/rdf-schema%23%3E%0A++++SELECT+%3Flabel%0A++++WHERE+%7B+%3Chttp%3A/dbpedia.org/resource/Asturias%3E+rdfs%3Alabel+%3Flabel+%7D%0A&output=json&results=json&format=json"

#https://docs.aws.amazon.com/neptune/latest/userguide/sparql-api-reference-mime.html
#
# You can choose the MIME type of a SPARQL response by sending an "Accept: type" header with the request.
# For example, curl -H "Accept: application/nquads ...".
# The available content types depend on the SPARQL query type.
#
# SELECT
#    application/sparql-results+json Default
#    application/sparql-results+xml
#    application/x-binary-rdf-results-table
#    text/tab-separated-values
#    text/csv
# ASK
#    application/sparql-results+json Default
#    application/sparql-results+xml
#    text/boolean
# CONSTRUCT
#    application/n-quads Default
#    application/rdf+xml
#    application/ld+json
#    application/n-triples
#    text/turtle
#    text/n3
#    application/trix
#    application/trig
#    application/sparql-results+json
# DESCRIBE
#    application/n-quads Default
#    application/rdf+xml
#    application/ld+json
#    application/n-triples
#    text/turtle
#    text/n3
#    application/trix
#    application/trig
#    application/sparql-results+json

################################################################################

# This is used in a Sparql endpoint. It extracts the SPARQL query
# from the CGI environment.
class SparqlEnvironment:
    # SPARQLWrapper uses CGI variables to specify the expected output type.
    # FieldStorage(
    #   None,
    #   None,
    #   [
    #       MiniFieldStorage(
    #          'query',
    #           '\n    PREFIX rdfs: <http:/www.w3.org/2000/01/rdf-schema#>\n    SELECT ?label\n    WHERE { <http:/dbpedia.org/resource/Asturias> rdfs:label ?label }\n'),
    #       MiniFieldStorage('output', 'json'),
    #       MiniFieldStorage('results', 'json'),
    #       MiniFieldStorage('format', 'json')])
    def __init__(self):
        import cgi
        self.m_arguments = cgi.FieldStorage()
        sys.stderr.write("\n")
        for i in self.m_arguments.keys():
            sys.stderr.write("%s => %s\n"%(i,self.m_arguments[i].value))
        sys.stderr.write("\n")

        self.m_query = self.m_arguments["query"].value
        output_type = self.m_arguments["output"].value

        sys.stderr.write("output_type=%s\n"%output_type)

        # Only "xml" works OK.
        if output_type == "json":
            self.m_mime_format = 'application/json'
            self.m_rdflib_format='json'
        elif output_type == "json-ld":
            self.m_mime_format = 'application/json'
            self.m_rdflib_format='json-ld'
        elif output_type == "xml":
            self.m_mime_format = 'application/xml'
            self.m_rdflib_format='xml'
        else:
            sys.stderr.write("Invalid output type:%s\n"%output_type)
            raise Exception("Invalid output type:"+output_type)
        sys.stderr.write("mime_format=%s\n"%self.m_mime_format)
        sys.stderr.write("rdflib_format=%s\n"%self.m_rdflib_format)

    def Query(self):
        return self.m_query

    def WriteTripleStoreAsString(self,grph):
        lib_util.WrtHeader(self.m_mime_format)
        try:
            # pip install rdflib-jsonld
            # No plugin registered for (json-ld, <class 'rdflib.serializer.Serializer'>)
            # rdflib_format = "pretty-xml"
            # strJson = grph.serialize( destination = None, format = rdflib_format)
            sys.stderr.write("len grph=%d\n"%len(grph))
            strJson = grph.serialize(format=self.m_rdflib_format)
            # strJson = grph.serialize(format='json-ld', indent=4)
        except Exception as exc:
            sys.stderr.write("Caught:%s\n"%exc)
            return
        sys.stderr.write("strJson=%s\n"%strJson)
        lib_util.WrtAsUtf(strJson)

################################################################################

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
# because they share the same subject, or commas if they share the subject and the predicate,
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
def aggregate_into_triples(raw_trpl):
    curr_trip = []
    cnt_trip = 0
    for block in raw_trpl:
        for elt in block:
            cnt_trip += 1
            curr_trip.append(elt)
            if cnt_trip == 3:
                yield curr_trip
                cnt_trip = 0
                curr_trip = []
    if cnt_trip == 3:
        yield curr_trip
    else:
        assert cnt_trip == 0


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
                        if isinstance(one_part_part_first_part,rdflib.plugins.sparql.parserutils.CompValue):
                            resu = pname_to_string(one_part_part_first_part)
                            return("TRPL_PREDICATE",resu)
                        else:
                            return("TRPL_URIREF",str(one_part_part_first_part))

    elif isinstance(pred,rdflib.term.Variable):
        # rdflib.term.Variable(u'p')
        return("TRPL_VARIABLE",str(pred))
    elif isinstance(pred,rdflib.term.BNode):
        return("TRPL_NODE",pred)
    else:
        print("ERROR")

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
    trpl_lst = aggregate_into_triples(raw_trpl)
    for one_trpl in trpl_lst:
        clean_trpl = decode_parsed_triple(one_trpl)
        yield clean_trpl

# This receives the key-value pairs taken from an identity extracted from the triples of a SPARQL query.
def ExtractClass(key_vals):
    # If the class is not defined, cannot query.
    # TODO: Consider base classes ??
    try:
        class_name = key_vals['rdf:type']
        del key_vals['rdf:type']
    except KeyError:
        return (None,None)

    return class_name, key_vals

# This receives the list of triples of a SPARQL query.
# It returns a dictionary of variables with constant attributes.
# The plan is to implement a minimalistic SPARQL engine,
# over WMI or WBEM.
# This is very restricted, because it does not work if there are joins.
# Also, the CIM class of the object must be known.
def ExtractEntitiesWithConstantAttributes(lst_triples):
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

class EntityQuery:
    def __init__(self,variable_name):
        self.m_variable_name = variable_name
        self.m_input_variables = set()
        self.m_attributes = {}

    def __repr__(self):
        resu = str(self.m_attributes)
        resu += " <= " + str(list(self.m_input_variables))
        return resu

class QueryVariable:
    def __init__(self,variable_name):
        self.m_variable_name = variable_name

    def __repr__(self):
        return "??" + self.m_variable_name + "??"

def ExtractEntitiesWithVariableAttributes(lst_triples):
    dictEntitiesByVariable = {}

    # Gathers attributes of objects.
    for one_triple in lst_triples:
        if one_triple[0][0] != "TRPL_VARIABLE":
            continue
        # The predicate type could be "TRPL_VARIABLE"
        if one_triple[1][0] != "TRPL_PREDICATE":
            continue
        if one_triple[2][0] == "TRPL_LITERAL":
            attribute_value = one_triple[2][1]
        elif one_triple[2][0]  == "TRPL_VARIABLE":
            attribute_value = QueryVariable( one_triple[2][1] )
        else:
            continue

        variable_name = one_triple[0][1]
        try:
            class_dict = dictEntitiesByVariable[variable_name]
        except KeyError:
            class_dict = {}
            dictEntitiesByVariable[variable_name] = class_dict
        class_dict[one_triple[1][1]] = attribute_value

    return dictEntitiesByVariable

# This returns an iterator on objects.
def ExecuteQueryEntities(class_name, key_values):
    qry = lib_util.SplitMonikToWQL(key_values,class_name)
    print(qry)
    # Returns one element, for testing.
    if class_name == "CIM_Process":
        return [
            { "survol:pid":123,"survol:ppid":456,"survol:user":"rchateau"},
            { "survol:pid":456,"survol:ppid":789,"survol:user":"rchateau"},
        ]
    if class_name == "CIM_DataFile":
        return [
            { "survol:user":"rchateau","survol:runs":"firefox.exe"},
            { "survol:user":"rchateau","survol:runs":"explorer.exe"},
        ]
    return None


class Loop:
    def __init__(self,class_name,key_values):
        self.m_class_name = class_name
        self.m_key_values = key_values

def Evaluate( lst_loops, index, known_variables, tuple_results):
    if index == len(lst_loops):
        yield tuple_results
        return
    curr_loop = lst_loops[0]

    key_values = {}
    lst_variables = {}
    for key_attribute in curr_loop.m_key_values:
        value_attribute = curr_loop.m_key_values[key_attribute]
        if isinstance(value_attribute,QueryVariable):
            variable_name = value_attribute.m_variable_name
            if variable_name in known_variables:
                key_values[key_attribute] = known_variables[variable_name]
            else:
                # Variable is not known yet
                lst_variables[variable_name] = key_attribute
        else:
            key_values[key_attribute] = value_attribute

    print("lst_variables=",lst_variables)
    for oneEntity in ExecuteQueryEntities(curr_loop.m_class_name, key_values):
        print("oneEntity=",oneEntity)
        for variable_name in lst_variables:
            known_variables[variable_name] = oneEntity[lst_variables[variable_name]]
        tmp_results = tuple_results + (oneEntity,)
        tuple_results = Evaluate( lst_loops, index + 1, known_variables, tmp_results)
        yield tuple_results

def PrintAsLoops(dictEntitiesByVariable):
    lst_loops = []

    for variable_name in dictEntitiesByVariable:
        class_name, key_values = ExtractClass( dictEntitiesByVariable[variable_name] )
        lst_loops.append( Loop(class_name, key_values) )

    itr_tuple_results = Evaluate(lst_loops,0,{},())
    for tuple_results in itr_tuple_results:
        print(tuple_results)

# Quand on a un triplet de cette forme, trouver toutes les proprietes
# litterales relatives au sujet.
# Subj: ('VARIABLE=', 't')
# Pred: ('Predicate', u'rdf:type')
# Obj: ('litt_string', 'CIM_Process')# On peut alors en faire des requetes WMI ou WBEM, eventuellement.
#
# En theorie, c'est toujours possible mais probablement tres lent.
#
# Si on a les bons attributs, on peut executer le script principal dans survol.

##################################################################################

# Interface: UpdateTripleStoreSnapshotWithSparqlQuery:
# - On recoit une requete, qu'on parse en une liste de triplets RDF.
# - Ensuite, on enrichit le graphe resultant.

##################################################################################

# Algorithme possible si on ne peut pas separer les entites a cause de variables.
# On prend les triplets.
# On les trie en se basant sur les variables.
# Si les entites sont bien separees, les triplets qui y font references
# doivent se retrouver groupees.
# A la fin, il doit suffire de rassembler les triplets par groupes:
# - Des entites.
# - Des associators.
# Quand une variable se retrouve dans le groupe suivant,
# ca implique une loop sur des queries WMI.
#
# Pour rassembler les elements d'une entite:
# Pour un subject donne, on fait venir en premier le triplet qui mentionne la classe.
#  => "select * from <classe>"
# Puis tous les triplets qui mentionnent un attribut litteral
#  => + " where <key> = <value>"
#
# Si les triplets suivants dependent du premier, renvoyer des expressions SPARQL avec des variables a remplacer.
# Donc, renvoyer une liste de tuples:
# [
#   [ ("var1","var2"), "select var3,var4 from xxx where k1=?var1 and k2=?var3",  ["var3","var4"] ],
# ]
# Est-ce que ca marche avec les ASSOCIATORS et REFERENCES ?
# Comment ordonner les boucles ?
#
# Si un groupe de triplet a une variable en commun, essayer "associator".
# Dans le cas general, se contenter de boucles.

# La methode est utilisable aussi pour WBEM et peut-etre aussi si enumerate_*.py

# For each predicate, get the list of scripts returning data for this predicate.
# See Test_package_dis.py
# This -possibly- implies classes (But this is not sure).
# Maybe this is only true for the function __init__.AddInfo().
# But this is a hint to identify the class of each variable.

# La relation "predicat" => [scripts] peut etre batie avec Test_package_dis.py
# en analysant le script, mais on peut aussi analyser le contenu des anciens triplestores
# resultat de l'execution des scripts au prealable, construire un historique
# et meme l'exploiter avec du pattern matching en recherchant des triplets similaires.

# For each variable whose class is identified, or suggested.
# For each variable of a given class, see if there are values for each attribute
# of its ontology.

# If yes, it means that the object can be identified.
# Then take the list of scripts for this class, returning these predicates.
# Possibly all scripts: Not many data should be returned.

# If no, we cannot identify the variable, then use the function Search() for this class,
# with the few key-value pairs if the object is a literal.
# There could be a default Search() function based on WMI or WBEM,
# but this is optional, because possibly very slow.
# There must be an upper limit on the number of objects returned by Search().

# The results can be mixed with WMI data by merging the results of both executions.
# Unfortunately, on the other hand, it prevents any join.

# Meme si on separe bien les entites,
# on ne peut pas, dans le cas general, lister les items en focntions des attributs,
# car rien n'indique qu'on aura tous ces attributs.
# Il faut donc avoir pour chaque classe une fonction d'enumeration prenant
# des triplets "key" "operator" "value"
# ou bien des paires "key" "operator/value" qui rendront tous les objects qui matchent.
# Evidemment, on va rendre des generateurs pour ne pas faire la meme erreur que WBEM.
# Libre a la fonction de faire ce qu'elle veut.
# Si un seul object ou bien si les attributs sont la clef, on renvoie l'URL de l'objet.
# D'ailleurs on ne renvoie que des URLS d'objet, avec les bonnes clefs.

# Tri des entites:
# Actuellement, on les rassemble avec le sujet. Notons que sujet et object peuvent etre inverses.
# Le predicat et la valeur doivent etre connus.
# Maintenant, on va trier en utilisant les variables:
# Pour simplifier, le predicat doit etre connu.
# tripletA(v1) > tripletB(v1,v2)
# tripletA(v1) == tripletB(v1)

