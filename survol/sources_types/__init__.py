"""
Top-level scripts directory
"""

# Special syntax for Doxygen
# https://stackoverflow.com/questions/4302870/doxygen-syntax-in-python

## \mainpage Scripts documentation
#
# Survol library is made of packages and subpackages which represents its classes model.
# Adding classes, namespaces or scripts is done by addng files or file trees
# in this hierarchy.
#
#  \section cls_vs_ns Classes vs namespaces
#
# A class is a module where the function EntityOntology() is present,
# whether it is defined by the module or one of its parents modules.
# The return value of EntityOntology() is a list of string, each representing an attribute of the class.
# If a module nor none of its parent modules define the function EntityOntology(), it is a namespace.
# Classes which are also defined in CIM must follow the same attributes conventions.
#
# Namespaces have a different meaning in Survol and CIM. For Survol, it is just a Python module
# which does not define a class for Survol. For CIM, it is another entity.
# CIM namespaces are not taken into account, which is not a problem because all classes
# shared by CIM and Survol are in the "root/CimV2" namespace.
#
#  \section step1 Adding user code
#
# To add a new class, or new scripts, to Survol,
# one just need to copy a file tree at the right place in this source tree.
# Class-specific functions are inherited. New packages, if invalid for any reason,
# are simply not taken into account, and their dependencies disabled.
# The error message, and the reason for disabling a script, can be displayed
# by ticking the checkbox "View all scripts".
#
#

# def EntityOntology():
# 	return ( ["Name"],)
#
# # This must add information about the user.
# def AddInfo(grph,node,entity_ids_arr):
# 	# Nothing to do.
# 	return
