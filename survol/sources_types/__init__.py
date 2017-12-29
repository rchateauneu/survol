"""
Top-level scripts directory
"""

# Special syntax for Doxygen
# https://stackoverflow.com/questions/4302870/doxygen-syntax-in-python

## \mainpage Scripts documentation
#
# Survol library is made of packages and subpackages which represents its classes model.
#
#  \subsection cls_vs_ns Classes vs namespaces
#
# A class is a module where the function Ontology() is present,
# whether it is defined by the module or one of its parents modules.
# The return value of EntityOntology() is a list of string, each representing an attribute of the class.
# If a module nor none of its parent modules define the function EntityOntology(), it is a namespace.
#
#  \subsection step1 Adding user code
#
# To add a new class, or new scripts, to Survol,
# one just need to copy a file tree at the right place in this source tree.
#
#

# def EntityOntology():
# 	return ( ["Name"],)
#
# # This must add information about the user.
# def AddInfo(grph,node,entity_ids_arr):
# 	# Nothing to do.
# 	return
