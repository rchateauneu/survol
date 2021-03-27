#!/usr/bin/env python

"""
Search SQL queries from source files.
"""

import os
import os.path
import re
import sys

import lib_uris
import lib_sql
import lib_util
import lib_common


# Many types of source file may contain SQL queries.
# Files matching these extensions are parsed with regular expressions, to find bits if SQL queries.
_extensions_sql_sources_files = [
    ".c", ".cc", ".cxx", ".cpp", ".c++", ".java", ".ii", ".ixx", ".ipp", ".i++",
    ".pc", ".pcc"
    ".inl", ".idl", ".ddl", ".odl",
    ".h", ".hh", ".hxx", ".hpp", ".h++",
    ".cs", ".d", ".php", ".php4", ".php5", ".phtml", ".inc",
    ".py", ".pyw",
    ".f90", ".f", ".for",
    ".tcl", ".as", ".js",
    ".sh", ".csh", ".bash",
    ".sql", ".pls", ".pks"
]


def Usable(entity_type, entity_ids_arr):
    """Filename must have proper file extension"""
    fil_nam = entity_ids_arr[0]
    fil_ext = os.path.splitext(fil_nam)[1]
    if fil_ext.lower() in _extensions_sql_sources_files:
        return True

    # On Unix, we could also check if the file is a Shell script, whatever the extension is.
    return os.path.isdir(fil_nam)

# There must be another script for object files and libraries,
# because the search should not be done in the entire file,
# but only in the DATA segment.


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    fil_nam = cgiEnv.GetId()

    grph = cgiEnv.GetGraph()

    node_file = lib_uris.gUriGen.FileUri(fil_nam)

    try:
        # The regular expressions are indexed with a key such as "INSERT", "SELECT" etc...
        # which gives a hint about what the query does, and is transformed into a RDF property.
        # TODO: Store the compiled regular expressions.
        # This creates a dictionary mapping the RDF property to the compiled regular expression.
        dict_regex_sql = lib_sql.SqlRegularExpressions()

        arr_props = []
        for rgx_key in dict_regex_sql:
            rgx_sql = dict_regex_sql[rgx_key]
            rgx_prop = lib_common.MakeProp(rgx_key)
            arr_props.append(rgx_prop)

            compiled_rgx = re.compile(rgx_sql, re.IGNORECASE)

            op_fil = open(fil_nam, 'r')
            for lin_fil in op_fil:
                matched_sqls = compiled_rgx.findall(lin_fil)

                # TODO: For the moment, we just print the query. How can it be related to a database ?
                for sql_qry in matched_sqls:
                    grph.add((node_file, rgx_prop, lib_util.NodeLiteral(sql_qry)))
            op_fil.close()

    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:%s. Protection ?" % str(exc))

    cgiEnv.OutCgiRdf("LAYOUT_RECT", arr_props)


if __name__ == '__main__':
    Main()

