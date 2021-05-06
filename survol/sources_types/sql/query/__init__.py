"""
Abstract SQL query
"""

import re
import sys
import logging

import lib_uris
import lib_util
import lib_common


class CgiPropertyB64(str):
    """
    This behaves like a string plus some properties for serialization.
    """
    
    # TODO: It would be simpler to allow any string to be encoded in B64,
    # TODO: ... and detect on-the-fly if is encoded or not.
    # TODO: The consequence is that the encoding would be separate from the data,
    # TODO: ... and it would not be necessary to have a special processing for any datatype
    # TODO: ... whose representation cannot be stored in n URL.
    def __new__(cls, prop_name):
        return super(CgiPropertyB64, cls).__new__(cls, prop_name)

    def ValueEncode(self, value_clear):
        return lib_util.Base64Encode(value_clear)

    def ValueDecode(self, value_coded):
        return lib_util.Base64Decode(value_coded)

    def ValueDisplay(self, value_clear):
        return lib_util.html_escape(value_clear)


# TODO: Use Base64 encoding for all parameters when they cannot be part of an url.
class CgiPropertyQuery(CgiPropertyB64):
    def __new__(cls):
        return super(CgiPropertyQuery, cls).__new__(cls, "Query")


# This array will be concatenated to other strings, depending of the origin of the query: database,
# process memory, file content.
def EntityOntology():
    return ([CgiPropertyQuery(),],)


def MakeUri(str_query, derived_entity="sql/query", **kwargs):
    """The SQL query is encoded in base 64 because it contains many special characters which are too complicated to
    encode as HTML entities. This is not visible as EntityName() does the reverse decoding."""

    # TODO: This is called from other classes like that: sql_query.MakeUri( strQuery, "oracle/query", Db = theDb )
    # TODO: This should rather rely on CgiPropertyB64, or have a fully generic solution for CGI-incompatible strings.
    str_query_encoded = lib_util.Base64Encode(str_query)
    # The result might be: { "Query" : str_query_encoded, "Pid" : thePid  }

    # Rather CgiPropertyQuery() instead of "Query"
    all_keyed_args = {"Query": str_query_encoded}
    all_keyed_args.update(kwargs)
    # Maybe we could take the calling module as derived entity ?
    return lib_uris.gUriGen.node_from_dict(derived_entity, all_keyed_args)


def AddInfo(grph, node, entity_ids_arr):
    str_query = entity_ids_arr[0]


# TODO: It should not strip blanks between simple-quotes.
def _stripblanks(text):
    lst = text.split('"')
    for i, item in enumerate(lst):
        if not i % 2:
            lst[i] = re.sub(r"\s+", " ", item)
    return '"'.join(lst)


def EntityName(entity_ids_arr):
    """This is dynamically called from the function _entity_array_to_label() in lib_naming.py.
    It returns a printable string, given the url arguments."""

    # TODO: Problem, this is not compatible with variable arguments.
    resu = lib_util.Base64Decode(entity_ids_arr[0])
    resu = lib_util.html_escape(resu)
    resu = _stripblanks(resu)
    return resu


def GetEnvArgs(cgiEnv):
    """This extracts the arguments from the URL. We make a function from it so that it wraps the decoding."""
    sql_query_encode = cgiEnv.m_entity_id_dict["Query"]
    sql_query = lib_util.Base64Decode(sql_query_encode)
    return sql_query


def EntityNameUtil(text_prefix, sql_query):
    """Only cosmetic reasons: The displayed text should not be too long, when used as a title."""
    resu = lib_util.Base64Decode(sql_query)
    resu = lib_util.html_escape(resu)
    resu = _stripblanks(resu)

    len_fil_nam = len(text_prefix)
    len_resu = len(resu)
    len_tot = len_fil_nam + len_resu
    len_maxi = 50
    len_diff = len_tot - len_maxi
    if len_diff > 0:
        len_resu -= len_diff
        if len_resu < 30:
            len_resu = 30

        return text_prefix + ":" + resu[:len_resu] + "..."
    else:
        return text_prefix + ":" + resu
