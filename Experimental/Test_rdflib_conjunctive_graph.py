"""
An RDFLib ConjunctiveGraph is an (unnamed) aggregation of all the named graphs
within a Store. The :meth:`~rdflib.graph.ConjunctiveGraph.get_context`
method can be used to get a particular named graph for use such as to add
triples to, or the default graph can be used

This example shows how to create named graphs and work with the
conjunction (union) of all the graphs.
"""

#import rdflib.plugins.memory
from rdflib import Namespace, Literal, URIRef
from rdflib.graph import Graph, ConjunctiveGraph
# from rdflib.plugins.stores.memory import Memory
from rdflib.plugins.memory import IOMemory


def DoTheTestMemory():
    ns = Namespace("http://love.com#")

    # AssertionError: ConjunctiveGraph must be backed by a context aware store.
    mary = URIRef("http://love.com/lovers/mary")
    john = URIRef("http://love.com/lovers/john")

    cmary = URIRef("http://love.com/lovers/context_mary")
    cjohn = URIRef("http://love.com/lovers/context_john")

    # my_store = Memory()
    store_input = IOMemory()

    gconjunctive = ConjunctiveGraph(store=store_input)
    gconjunctive.bind("love", ns)

    # add a graph for Mary's facts to the Conjunctive Graph
    gmary = Graph(store=store_input, identifier=cmary)
    # Mary's graph only contains the URI of the person she love, not his cute name
    gmary.add((mary, ns["hasName"], Literal("Mary")))
    gmary.add((mary, ns["loves"], john))

    # add a graph for John's facts to the Conjunctive Graph
    gjohn = Graph(store=store_input, identifier=cjohn)
    # John's graph contains his cute name
    gjohn.add((john, ns["hasCuteName"], Literal("Johnny Boy")))

    # enumerate contexts
    print("Input contexts")
    for c in gconjunctive.contexts():
        print("-- %s " % c)

    # separate graphs
    if False:
        print("===================")
        print("GJOHN")
        print(gjohn.serialize(format="n3").decode("utf-8"))
        print("===================")
        print("GMARY")
        print(gmary.serialize(format="n3").decode("utf-8"))
        print("===================")

    # full graph
    print("===================")
    print("GCONJUNCTIVE NATIVE")
    print(gconjunctive.serialize(format="n3").decode("utf-8"))

    # query the conjunction of all graphs
    xx = None
    for x in gconjunctive[mary : ns.loves / ns.hasCuteName]:
        xx = x
    print("Q: Who does Mary love?")
    print("A: Mary loves {}".format(xx))


    # Ensuite, on sauve un seul sous-graphe, puis on le recharge et le resultat doit etre le meme.
    gjohn.serialize(destination='gjohn_copy.xml', format='xml')
    gmary.serialize(destination='gmary_copy.xml', format='xml')

    gjohn_copy = Graph()
    gjohn_copy.parse('gjohn_copy.xml', format='xml')
    gmary_copy = Graph()
    gmary_copy.parse('gmary_copy.xml', format='xml')

    if True:
        print("===================")
        print("GJOHN")
        print(gjohn_copy.serialize(format="n3").decode("utf-8"))
        print("===================")
        print("GMARY")
        print(gmary_copy.serialize(format="n3").decode("utf-8"))
        print("===================")


    print("===================")
    print("GCONJUNCTIVE WITH QUADS")
    print(list(gconjunctive.quads(None)))
    print("===================")

    gconjunctive.serialize(destination='gconjunctive_copy.xml', format='xml')

    gconjunctive_copy = ConjunctiveGraph()
    gconjunctive_copy.parse('gconjunctive_copy.xml', format='xml')

    print("===================")
    print("GCONJUNCTIVE AS CONJUNCTIVE")
    print(gconjunctive_copy.serialize(format="n3").decode("utf-8"))
    print("Output contexts")
    for c in gconjunctive_copy.contexts():
        print("-- %s " % c)
    print("===================")

    gconjunctive_graph_copy = Graph()
    gconjunctive_graph_copy.parse('gconjunctive_copy.xml', format='xml')

    print("===================")
    print("GCONJUNCTIVE AS GRAPH")
    print(gconjunctive_graph_copy.serialize(format="n3").decode("utf-8"))
    #print("Output contexts")
    #for c in gconjunctive_graph_copy.contexts():
    #    print("-- %s " % c)
    print("===================")



def DoTheTestSleepyCat():
    ns = Namespace("http://love.com#")

    # AssertionError: ConjunctiveGraph must be backed by a context aware store.
    mary = URIRef("http://love.com/lovers/mary")
    john = URIRef("http://love.com/lovers/john")

    cmary = URIRef("http://love.com/lovers/context_mary")
    cjohn = URIRef("http://love.com/lovers/context_john")

    # my_store = Memory()
    store_input = IOMemory()

    gconjunctive = ConjunctiveGraph(store=store_input)
    gconjunctive.bind("love", ns)

    # add a graph for Mary's facts to the Conjunctive Graph
    gmary = Graph(store=store_input, identifier=cmary)
    # Mary's graph only contains the URI of the person she love, not his cute name
    gmary.add((mary, ns["hasName"], Literal("Mary")))
    gmary.add((mary, ns["loves"], john))

    # add a graph for John's facts to the Conjunctive Graph
    gjohn = Graph(store=store_input, identifier=cjohn)
    # John's graph contains his cute name
    gjohn.add((john, ns["hasCuteName"], Literal("Johnny Boy")))

    # enumerate contexts
    print("Input contexts")
    for c in gconjunctive.contexts():
        print("-- %s " % c)

    # separate graphs
    if False:
        print("===================")
        print("GJOHN")
        print(gjohn.serialize(format="n3").decode("utf-8"))
        print("===================")
        print("GMARY")
        print(gmary.serialize(format="n3").decode("utf-8"))
        print("===================")

    # full graph
    print("===================")
    print("GCONJUNCTIVE NATIVE")
    print(gconjunctive.serialize(format="n3").decode("utf-8"))

    # query the conjunction of all graphs
    xx = None
    for x in gconjunctive[mary : ns.loves / ns.hasCuteName]:
        xx = x
    print("Q: Who does Mary love?")
    print("A: Mary loves {}".format(xx))


    # Ensuite, on sauve un seul sous-graphe, puis on le recharge et le resultat doit etre le meme.
    gjohn.serialize(destination='gjohn_copy.xml', format='xml')
    gmary.serialize(destination='gmary_copy.xml', format='xml')

    gjohn_copy = Graph()
    gjohn_copy.parse('gjohn_copy.xml', format='xml')
    gmary_copy = Graph()
    gmary_copy.parse('gmary_copy.xml', format='xml')

    if True:
        print("===================")
        print("GJOHN")
        print(gjohn_copy.serialize(format="n3").decode("utf-8"))
        print("===================")
        print("GMARY")
        print(gmary_copy.serialize(format="n3").decode("utf-8"))
        print("===================")


    print("===================")
    print("GCONJUNCTIVE WITH QUADS")
    print(list(gconjunctive.quads(None)))
    print("===================")

    gconjunctive.serialize(destination='gconjunctive_copy.xml', format='xml')

    gconjunctive_copy = ConjunctiveGraph()
    gconjunctive_copy.parse('gconjunctive_copy.xml', format='xml')

    print("===================")
    print("GCONJUNCTIVE AS CONJUNCTIVE")
    print(gconjunctive_copy.serialize(format="n3").decode("utf-8"))
    print("Output contexts")
    for c in gconjunctive_copy.contexts():
        print("-- %s " % c)
    print("===================")

    gconjunctive_graph_copy = Graph()
    gconjunctive_graph_copy.parse('gconjunctive_copy.xml', format='xml')

    print("===================")
    print("GCONJUNCTIVE AS GRAPH")
    print(gconjunctive_graph_copy.serialize(format="n3").decode("utf-8"))
    #print("Output contexts")
    #for c in gconjunctive_graph_copy.contexts():
    #    print("-- %s " % c)
    print("===================")




if False:
    DoTheTestMemory()

DoTheTestSleepyCat()