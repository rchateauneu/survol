import rdflib

my_query = """
        prefix cim:  <http://www.primhillcomputers.com/ontology/survol#>
        prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#>
        select ?my_dir_name3
        where {
        ?my_dir1 rdf:type cim:Win32_Directory .
        ?my_dir1 cim:Name "C:" .
        ?my_assoc_dir1 rdf:type cim:Win32_SubDirectory .
        ?my_assoc_dir1 cim:GroupComponent ?my_dir1 .
        ?my_assoc_dir1 cim:PartComponent ?my_dir2 .
        ?my_dir2 rdf:type cim:Win32_Directory .
        ?my_assoc_dir2 rdf:type cim:Win32_SubDirectory .
        ?my_assoc_dir2 cim:GroupComponent ?my_dir2 .
        ?my_assoc_dir2 cim:PartComponent ?my_dir3 .
        ?my_dir3 rdf:type cim:Win32_Directory .
        ?my_dir3 cim:Name ?my_dir_name3 .
        }
"""

my_graph = rdflib.Graph()
my_graph.parse("content_snippet_Testing_Win32_Directory_Win32_SubDirectory_Win32_SubDirectory.txt", format="xml")
print("Number of triples", len(my_graph))
my_results = my_graph.query(my_query)
for one_result in my_results:
    print(one_result)