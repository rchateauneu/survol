# RGB colors here: http://www.pagetutor.com/common/bgcolors216.html

import sys
import logging
import lib_util


# Graphic attributes for SVG and Dot. We could also use dot record nodes.
# On the other hand, it is convenient to have some control on the final SVG code.
#
#                                                shape        colorfill  colorbg   border is_rounded
_dict_graph_params = {
    "addr"                                   : ("rarrow",    "#FFFF99", "#FFFF99", 0, False),
    "CIM_Process"                            : ("component", "#99FF88", "#99FF88", 0, False),
    "CIM_Directory"                          : ("folder",    "#8899FF", "#8899FF", 0, False),
    "CIM_DataFile"                           : ("note",      "#88BBFF", "#88BBFF", 0, False),
    "LMI_Group"                              : ("plain",     "#88BBFF", "#88BBFF", 0, False),
    "CIM_ComputerSystem"                     : ("signature", "#CCFFCC", "#CCFFCC", 0, False),
    "memmap"                                 : ("tab",       "#CCFFCC", "#CCFFCC", 0, False),
    "CIM_LogicalDisk"                        : ("box3d",     "#FFCCFF", "#FFCC66", 0, False),
    "smbfile"                                : ("tab",       "#99CCFF", "#FFCC66", 0, True),
    "smbserver"                              : ("tab",       "#99CCFF", "#FFCC66", 0, True),
    "Win32_Share"                            : ("tab",       "#99CCFF", "#FFCC66", 0, True),
    "linker_symbol"                          : ("none",      "#99FFCC", "#FFCC66", 0, False),
    "LMI_Account"                            : ("octagon",   "#EEAAAA", "#FFCC66", 0, False),
    "Win32_Service"                          : ("component", "#EEAAAA", "#FFCC66", 0, False),
    "Win32_UserAccount"                      : ("octagon",   "#EEAAAA", "#FFCC66", 0, True),
}

_dflt_graph_params =                              ("none", "#FFFFFF", "#99BB88", 1, False)


def EntityClassToColor(sub_entity_graphic_class):
    """This color is used to generate HTML code in DOT."""
    if sub_entity_graphic_class:
        arr_attrs = TypeToGraphParams(sub_entity_graphic_class)
        bg_col = arr_attrs[1]
        return bg_col
    else:
        # If this is a script.
        return "#FFFFFF"


def color_lighter(obj_color):
    """This returns a RGB color slightly lighter than the input.
    It is used for tables where lines are alternatively lighter/darker."""
    def color_lighter_nocache(obj_color):
        def lighter_byte(X):
            dec = int(X,16)
            if dec < 13:
                dec +=2
            elif dec == 14:
                dec = 15
            return "0123456789ABCDEF"[dec]

        chars_list = [
            "#",
            lighter_byte(obj_color[1]),
            obj_color[2],
            lighter_byte(obj_color[3]),
            obj_color[4],
            lighter_byte(obj_color[5]),
            obj_color[6]]

        obj_color_light = "".join(chars_list)
        return obj_color_light

    try:
        return color_lighter.CacheMap[obj_color]
    except KeyError:
        lig = color_lighter_nocache(obj_color)
        color_lighter.CacheMap[obj_color] = lig
        return lig


color_lighter.CacheMap = dict()


# Returns graphic parameters given a type without namespace.
# For example "Win32_Service", "oracle/package"
# TODO: Should use lib_util.HierarchicalFunctionSearch
def TypeToGraphParams(type_without_ns):
    # Safety check.
    if type_without_ns.find(".") >= 0:
        raise "Invalid type_without_ns=%s" % type_without_ns

    type_without_ns = type_without_ns.replace("/", ".")

    # Fastest access from the cache.
    try:
        return _dict_graph_params[type_without_ns]
    except KeyError:
        vec_graph = type_to_graph_params_no_cache(type_without_ns)
        _dict_graph_params[type_without_ns] = vec_graph
    return vec_graph


def type_to_graph_params_no_cache(type_without_ns):
    """Gets the graphic attributes: Each of them comes from the module of the entity or an upper module."""

    # TODO: At the moment, we cannot distinguish between our entities (Defined in our modules) and
    # TODO: CIM properties which can only be stored but elsewhere. But CIM classes have no graphic attributes.

    vec_graph_functions = [
        "Graphic_shape", "Graphic_colorfill", "Graphic_colorbg", "Graphic_border", "Graphic_is_rounded"
    ]

    vec_props = []
    for idx_grph in range(len(vec_graph_functions)):
        g_func_name = vec_graph_functions[idx_grph]
        grph_func = lib_util.HierarchicalFunctionSearchNoCache(type_without_ns, g_func_name)

        if grph_func:
            grph_val = grph_func()
        else:
            # If no such function defined for this module and its ancestors.
            grph_val = _dflt_graph_params[idx_grph]
        vec_props.append(grph_val)

    return vec_props


def _build_pattern_node(tp):
    """This returns an array of format strings which are used to generate HTML code."""
    shape = tp[0]
    colorfill = tp[1]
    colorbg = tp[2]
    border = tp[3]
    is_rounded = tp[4]

    if is_rounded:
        style = 'style="rounded,filled"'
    else:
        style = 'style="filled"'

    # First element if this is a URI, second element if plain string.
    fmt_with_uri = '%s [ shape=' + shape + ', tooltip="%s", ' + style + ' fillcolor="' + colorfill + \
        '" color=%s label=< <table color="' + '#000000' + '"' + \
        " cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
        '<td href="%s" bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
        "</tr>"

    fmt_with_no_uri = '%s [ shape=' + shape + ', tooltip="%s", ' + style + ' fillcolor="' + colorfill + \
        '" color=%s label=< <table color="' + '#000000' + '"' + \
        " cellborder='0' cellspacing='0' border='" + str(border) + "'><tr>" + \
        '<td bgcolor="' + colorbg + '" colspan="%d">%s</td>' + \
        "</tr>"

    return [fmt_with_uri, fmt_with_no_uri]


# TODO: It is possible to avoid one level of cache. But this adds extra flexibility
# TODO: if there are more parameters than only the class.
_dict_type_to_patterns = {}


def _pattern_node(type_full):
    """Returns a HTML pattern given an entity type. Similar to TypeToGraphParams()
    but it removes the namespace if there is one."""

    # TODO: Three possible syntaxes for the type:
    # "root\CIMV2:CIM_AssociatedMemory" : WMI class     => Investigate base classes.
    # "root/CIMV2:CIM_AssociatedMemory" : WBEM class    => Investigate base classes.
    # "CIM_Process" or "oracle/table"   : Custom class  => Split.
    # We would need some sort of inheritance chains.
    try:
        return _dict_type_to_patterns[type_full]
    except KeyError:
        # This removes the WBEM or WMI namespace.
        the_type = type_full.split(":")[-1]
        array_graph_params = TypeToGraphParams(the_type)
        patt_array = _build_pattern_node(array_graph_params)
        _dict_type_to_patterns[type_full] = patt_array
        return patt_array


def WritePatterned(stream, a_type, subj_nam_tab, help_text, color, lab_h_ref, num_fields, lab_text, dict_lines):
    patt_array = _pattern_node(a_type)

    # TODO: The title and the elements might not have the same color.

    # TODO: At least, < and > in labels are correctly displayed, but not really clickable.
    # The best is to avoid them in entities names and urls.
    help_text = help_text.replace("\"", "&quot;")
    lab_text = help_text.replace("<", "&lt;").replace(">", "&gt;")
    lab_h_ref = lab_h_ref.replace("<", "&lt;").replace(">", "&gt;")

    try:
        if lab_h_ref:
            stream.write(patt_array[0] % (subj_nam_tab, help_text, color, lab_h_ref, num_fields, lab_text))
        else:
            stream.write(patt_array[1] % (subj_nam_tab, help_text, color, num_fields, lab_text))
    except UnicodeEncodeError:
        logging.debug("WritePatterned UnicodeEncodeError: Encoding=%s", sys.getdefaultencoding())
        return

    for key in lib_util.natural_sorted(dict_lines):
        try:
            # Brackets have a specific role in "dot" files syntax.
            # So this escapes them, to be correctly displayed by the browser.
            dict_lines_key = dict_lines[key]
            dict_lines_key = dict_lines_key.replace("[","&#91;").replace("]", "&#93;")
            dict_lines[key] = dict_lines_key
        except Exception as exc:
            dict_lines_key = "<td>WritePatterned: exc=%s</td>" % str(exc)

        stream.write("<tr>%s</tr>" % dict_lines_key)

    stream.write("</table> > ] \n")
