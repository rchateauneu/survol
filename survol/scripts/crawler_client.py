# This starts from an agent and tries every possible links,
# and can also connect to other agents.
# In a certain extent, it works like wget,
# but it has at least the same heuristics capability than crawler_server.py

# It builds a data model based on json serializing.
# It can also be used for testing.

# crawler_client.py http://url/.../entity.py?xid=...

# It uses the client library lib_client.py
# rdflib library to load the content of an URL.
#
# Algorithm A* : https://en.wikipedia.org/wiki/A*_search_algorithm
#
# What is the goal ? There can be several goals, one of them is to
# find a dependence between two nodes, a possible correlation:
# Examples:
# - Table accessed by two processes.
# - If a process is indirectly affected by a DLL.

# The solution is a global RDF container which is enriched as the algorithm
# is visiting the URLs.
#
# A priority queue (Also called "open set") contains nodes to expand.
# These nodes are pairs of Survol URLs:
# - a CIM object, or None.
# - One script taking possibly a CIM object (The first element of the pair).
#   The script might be "entity.py", which display general information
#   about a node, and also its scripts.
# The CIM node can always be deduced from the script parameters,
# therefore we might as well manipulate only scripts.
#
# The algorithm starts with an object or a list of script.
# At each step, the algorithm selects the best script (Possibly entity.py) and loads its content,
# which are nodes and links joining them.
# The content nodes is split into two sets:
# - The scripts nodes are added to the priority queue, paired with their node.
# - The non-scripts nodes (CIM objects) are merged into the global RDF container;
#   They are also added to the priority queue, paired with the "entity.py" script.
#
# Then the nodes are sorted with a specific comparison with the destination node:
# - Same classes or name spaces.
# - Levenshtein distance of the attributes.
# - Any shared attribute.
#
# The heuristic also applies when comparing scripts with the same CIM nodes,
# or scripts with no nodes, etc... We are comparing pairs.

#import survol

#print(dir(survol))
#print(survol.__file__)

import lib_client


