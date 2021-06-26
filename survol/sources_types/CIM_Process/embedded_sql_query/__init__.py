"""
Extraction of SQL queries from process memory.
"""

from sources_types.sql import query as sql_query_module

import lib_util

# Explanation about the object model:
# A directory defines a class if the __init__.py object contains a function named EntityOntology().
# Otherwise, it is a subclass of the parent directory. If no EntityOntology() function is defined
# in none of the parent directories, then it is a static class or a namespace.

# The result should be ["Query","Handle"]
# We do not know if CIM_Process.EntityOntology() is available.
def EntityOntology():
    return (["Query", "Handle"],)


# The SQL query is encoded in base 64 because it contains many special characters which would be too complicated to
# encode as HTML entities. This is not visible as EntityName() does the reverse decoding.
def MakeUri(str_query, the_pid):
    # TODO: We have hard-coded the process definition with "Handle".
    # TODO: The entity parameter should be passed differently, more elegant. Not sure.
    return sql_query_module.MakeUri(str_query, "CIM_Process/embedded_sql_query", Handle=the_pid)


def EntityName(entity_ids_arr):
    the_pid = entity_ids_arr[1]
    sql_query = entity_ids_arr[0]
    resu = sql_query

    # If the query contains double-quotes, it crashes Graphviz
    resu = resu.replace('"', "'")
    return "Pid " + str(the_pid) + ":" + resu
