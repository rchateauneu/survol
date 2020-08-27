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

ns = Namespace("http://love.com#")

# AssertionError: ConjunctiveGraph must be backed by a context aware store.
mary = URIRef("http://love.com/lovers/mary")
john = URIRef("http://love.com/lovers/john")

cmary = URIRef("http://love.com/lovers/mary")
cjohn = URIRef("http://love.com/lovers/john")

# my_store = Memory()
my_store = IOMemory()
print("my_store.context_aware=", my_store.context_aware)

g = ConjunctiveGraph(store=my_store)
g.bind("love", ns)

# add a graph for Mary's facts to the Conjunctive Graph
gmary = Graph(store=my_store, identifier=cmary)
# Mary's graph only contains the URI of the person she love, not his cute name
gmary.add((mary, ns["hasName"], Literal("Mary")))
gmary.add((mary, ns["loves"], john))

# add a graph for John's facts to the Conjunctive Graph
gjohn = Graph(store=my_store, identifier=cjohn)
# John's graph contains his cute name
gjohn.add((john, ns["hasCuteName"], Literal("Johnny Boy")))

# enumerate contexts
for c in g.contexts():
    print("-- %s " % c)

# separate graphs
print("===================")
print("GJOHN")
print(gjohn.serialize(format="n3").decode("utf-8"))
print("===================")
print("GMARY")
print(gmary.serialize(format="n3").decode("utf-8"))
print("===================")

# full graph
print(g.serialize(format="n3").decode("utf-8"))

# query the conjunction of all graphs
xx = None
for x in g[mary : ns.loves / ns.hasCuteName]:
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

print("===================")
print("GJOHN")
print(gjohn_copy.serialize(format="n3").decode("utf-8"))
print("===================")
print("GMARY")
print(gmary_copy.serialize(format="n3").decode("utf-8"))
print("===================")
