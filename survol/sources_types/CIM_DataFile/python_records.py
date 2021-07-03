#!/usr/bin/env python

"""
Classes methods from nm command
"""

# This get a list of classes and functions from a python file without importing it,
# and generates links to "record" objects.
# https://stackoverflow.com/questions/44698193/how-to-get-a-list-of-classes-and-functions-from-a-python-file-without-importing

"""
Python package dependencies
"""

import os
import ast
import logging

import lib_uris
import lib_common


def Usable(entity_type, entity_ids_arr):
    """Can run with Python files only"""

    fil_nam = entity_ids_arr[0]

    # But probably it is not enough and we should try to open it.
    fil_ext = os.path.splitext(fil_nam)[1]

    # Maybe this can be generalised to survol_python.pyExtensions
    return fil_ext.lower() == ".py"


def Main():
    cgiEnv = lib_common.ScriptEnvironment()

    py_fil_nam = cgiEnv.m_entity_dict["Name"]

    grph = cgiEnv.GetGraph()

    fil_node = lib_uris.gUriGen.FileUri(py_fil_nam)

    try:

        def show_info(function_node):
            logging.debug("Function:%s", dir(function_node))
            logging.debug("Function name:%s", function_node.name)
            for arg in function_node.args.args:
                # import pdb; pdb.set_trace()
                logging.debug("\tParameter name:%s", arg.arg)

        with open(py_fil_nam) as file:
            node = ast.parse(file.read())

        # functions = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        classes = [n for n in node.body if isinstance(n, ast.ClassDef)]

        # for function in functions:
        #     show_info(function)

        for class_ in classes:
            logging.debug("Class name:%s", class_.name)
            methods = [n for n in class_.body if isinstance(n, ast.FunctionDef)]
            for method in methods:
                show_info(method)




        grph.add((fil_node, None, None))
    except Exception as exc:
        lib_common.ErrorMessageHtml("File:%s Unexpected error:%s" % (py_fil_nam, str(exc)))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()


