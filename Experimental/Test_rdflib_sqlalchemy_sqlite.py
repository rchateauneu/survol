import rdflib
sqlite_uri = rdflib.Literal("sqlite:///toto.sqlite?mode=memory&cache=shared")

#"SQLAlchemy", "sqlite:///toto?mode=memory&cache=shared"
sqlite_ident = rdflib.URIRef("rdflib_test")
store_input = rdflib.plugin.get("SQLAlchemy", rdflib.store.Store)(identifier=sqlite_ident)
events_conjunctive_graph = rdflib.ConjunctiveGraph(store_input, identifier=sqlite_ident)
result_open=events_conjunctive_graph.open(sqlite_uri, create=True)
print("result_open=", result_open)

events_conjunctive_graph.add((rdflib.URIRef("aaa"), rdflib.URIRef("bbb"), rdflib.URIRef("ccc")))