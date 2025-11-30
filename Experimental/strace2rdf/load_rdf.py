# This loads with rdflib a RDF/XML file.
# This checking its conformance.
import sys
import datetime
import rdflib

survol_namespace = "http://www.primhillcomputers.com/survol#"

def QueryOpenProperties(g):
    """
    Arguments and return type of the system call "open"
    """
    print("QueryOpenProperties")
    sparql_query = """
        PREFIX survol: <%s>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?arg_label
        WHERE {
            ?call_class rdfs:label "open" .
            ?open_property rdfs:domain ?call_class .
            ?open_property rdfs:label ?arg_label .
        }
    """ % (survol_namespace)
    
    qres = g.query(sparql_query)
    args = sorted([str(row.arg_label) for row in qres])
    print("args=", args)
    assert args == ['__return_type__', 'flags', 'mode', 'pathname']
        
def QueryOpenPropertiesPrefix(g):
    """
    Arguments and return type of the system call "open"
    """
    print("QueryOpenPropertiesPrefix")
    sparql_query = """
        PREFIX survol: <%s>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?arg_label ?open_property
        WHERE {
            ?open_property rdfs:domain survol:open .
            ?open_property rdfs:label ?arg_label .
        }
    """ % (survol_namespace)

    qres = g.query(sparql_query)
    args = sorted([str(row.arg_label) for row in qres])
    print("args=", args)
    assert args == ['__return_type__', 'flags', 'mode', 'pathname']
        

def QuerySystemCallSubclasses(g):
    """
    Arguments and return type of the system call "open"
    """
    print("QuerySystemCallSubclasses")
    sparql_query = """
        PREFIX survol: <%s>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?class_label
        WHERE {
            ?call_class rdfs:subClassOf survol:SystemCall .
            ?call_class rdfs:label ?class_label .
            ?call_class rdf:type rdfs:Class.
        }
    """ % (survol_namespace)
    
    qres = g.query(sparql_query)
    classes = sorted([str(row.class_label) for row in qres])
    print("classes=", classes)
    assert classes == ['connect', 'execve', 'fchdir', 'open', 'openat', 'wait4']
        

def QueryOpenCallsStartTimePathname(g):
    print("QueryCallsOpen")
    sparql_query = """
        PREFIX survol: <%s>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX schema: <http://schema.org/#>
        SELECT *
        WHERE {
            ?open_call rdf:type survol:open .
            ?open_call schema:StartTime ?start_time .
            ?open_call survol:pathname ?pathname .
            ?open_call survol:CallingProcess ?calling_process .
        }
    """ % (survol_namespace)
    qres = g.query(sparql_query)
    
    for row in qres:
        topy = row.start_time.toPython()
        assert type(topy) == datetime.time
        assert topy.hour >= 0 and topy.hour < 60
        assert topy.minute >= 0 and topy.minute < 60
        

def QueryEverything(g):
    # http://www.primhillcomputers.com/survol#open.CallId=553 http://www.w3.org/1999/02/22-rdf-syntax-ns#type http://www.primhillcomputers.com/survol#open
    # http://www.primhillcomputers.com/survol#open.CallId=243 http://schema.org/#EndTime "00:33:40.122898"^^xsd:dateTime
    sparql_query = """
        PREFIX survol: <%s>
        SELECT ?s ?p ?o
        WHERE {
            ?s ?p ?o .
        }
    """ % (survol_namespace)
    qres = g.query(sparql_query)
    for row in qres:
        # print(f"{row.aname} knows {row.bname}")
        print(f"{row.s} {row.p} {row.o}")


def QueryClassesWithoutPrefix(g):
    sparql_query = """
        PREFIX survol: <%s>
        SELECT ?s ?p 
        WHERE {
            ?s ?p <http://www.w3.org/2000/01/rdf-schema#Class> .
        }
    """ % (survol_namespace)
    qres = g.query(sparql_query)
    for row in qres:
        # print(f"{row.aname} knows {row.bname}")
        print(f"{row.s} {row.p}")


"""
http://www.primhillcomputers.com/survol#connect http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#CIM_DataFile http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#execve http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#open http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#SystemCall http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#fchdir http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#wait4 http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#openat http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#CIM_Process http://www.w3.org/1999/02/22-rdf-syntax-ns#type
http://www.primhillcomputers.com/survol#CIM_Directory http://www.w3.org/1999/02/22-rdf-syntax-ns#type
"""
def QueryClassesWithPrefix(g):
    print("QueryClassesWithPrefix")
    sparql_query = """
        PREFIX survol: <%s>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        SELECT ?s ?p 
        WHERE {
            ?s ?p rdfs:Class .
        }
    """ % (survol_namespace)
    qres = g.query(sparql_query)
    for row in qres:
        print(f"{row.s} {row.p}")


def RunQuery(g):
    if False:
        knows_query = """
        SELECT DISTINCT ?aname ?bname
        WHERE {
            ?a foaf:knows ?b .
            ?a foaf:name ?aname .
            ?b foaf:name ?bname .
        }"""

        qres = g.query(knows_query)
        for row in qres:
            print(f"{row.aname} knows {row.bname}")

        sparql_query = """
            PREFIX survol: <%s>
            SELECT ?datafile_name WHERE {
                ?url_directory a survol:CIM_Directory .
                ?url_datafile a survol:CIM_DataFile .
                ?url_directory survol:CIM_DirectoryContainsFile ?url_datafile .
                ?url_datafile survol:Name ?datafile_name .
                ?url_directory survol:Name "%s" .
            }
        """ % (survol_namespace, _temp_dir_path)


def LoadRdfFile(filename):
    print("filename=", filename)
    g = rdflib.Graph()
    g.parse(filename)
    QueryOpenProperties(g)
    QuerySystemCallSubclasses(g)
    QueryOpenPropertiesPrefix(g)
    QueryOpenCallsStartTimePathname(g)
    if False:
        RunQuery(g)
        QueryClassesWithoutPrefix(g)
        QueryClassesWithPrefix(g)

    # Ajouter des requetes Sparql standards pour tester le concept d'analyse des dependances:
    # - Les sous-process.
    # - Les dependances des fichiers.
    # - Les commandes.

for oneFile in sys.argv[1:]:
    LoadRdfFile(oneFile)
