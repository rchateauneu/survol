import sys
import json
import os
import re
import collections
import six
import subprocess
import cgi

import lib_kbase
import lib_naming
import lib_patterns
import lib_grammar
import lib_exports

import lib_util
from lib_util import TimeStamp

import lib_properties
from lib_properties import pc


def _truncate_in_space(lab_text, max_len_lab):
    """
    This truncates a string to a given length but tries to cut
    at a space position instead of splitting a word.
    """
    if len(lab_text) > max_len_lab:
        idx = lab_text.find(" ", max_len_lab)
        # sys.stderr.write("idx=%d\n"%idx)
        if idx < 0:
            idx = max_len_lab

            # BEWARE: This must not fall in the middle of an html entity "&amp;", etc... ...
            idx_semi_colon = lab_text.find(";", idx)
            # sys.stderr.write("idx_semi_colon=%d\n"%idx_semi_colon)
            if idx_semi_colon < 0:
                idx = max_len_lab
            else:
                idx = idx_semi_colon + 1 # Just after the semi-colon.

        # sys.stderr.write("labText=%s idx=%d\n"%(labText,idx))
        return lab_text[:idx]
    else:
        return lab_text


# TODO: Take the colors from the CSS html_exports.css
# TODO: Add a tool tip. Also, adapt the color to the context.
_pattern_edge_oriented = "\t%s -> %s [ color=%s, label=< <font point-size='10' " + \
    "color='#336633'>%s</font> > ] ;\n"
_pattern_edge_bidirect = "\t%s -> %s [ dir=both color=%s, label=< <font point-size='10' " + \
    "color='#336633'>%s</font> > ] ;\n"


def external_url_to_title(ext_url):
    """Returns a string for an URL which might be different from "entity.py" etc...
    Depending on where it comes from, "%2F" instead of "/" ... ugly.
    BEWARE: This is completely experimental. See if "Yawn" is actually used."""
    if re.match( ".*/yawn/.*", ext_url) or re.match(".*%2Fyawn%2F.*", ext_url):
        return "Yawn"

    py_nam_mtch = re.match( ".*/([^.]+).py.*", ext_url)
    if py_nam_mtch:
        py_nam = py_nam_mtch.group(1)

        # After all, the script might be entity
        if py_nam == "entity":
            obj_nam, entity_graphic_class, entity_id = lib_naming.ParseEntityUri(ext_url)
            return obj_nam

        try:
            # TODO: See lib_naming.scripts_to_titles
            basNamToTxt = {
                "objtypes_wbem": "Subtypes", # This key is duplicated !!!!
                "file_directory": "Subdir",
                "file_to_mime": "MIME",
                "objtypes_wmi": "WMI tree",
                "objtypes_wbem": "WBEM hier.",
                "class_type_all": "Cross class",
                "dir_to_html": "DIR"
            }
            return basNamToTxt[py_nam]
        except:
            return py_nam.replace("_", " ").capitalize()
    else:
        # sys.stderr.write("extUrl=%s\n"%extUrl)
        return "Literal:" + ext_url


# These properties must have their object displayed not as a separated node,
# but as a link displayed with a string, a plain HREF.
_flat_properties_list = [pc.property_rdf_data_nolist1, pc.property_rdf_data_nolist2, pc.property_rdf_data_nolist3]


def is_flat_property(key):
    return key in _flat_properties_list


def Rdf2Dot(grph, logfil, stream, collapsed_properties, commutative_properties):
    """Used for transforming into SVG format.
    If from entity.py, collapsed_properties = pc.property_directory,pc.property_script """
    fields_set = collections.defaultdict(list)

    # This maps RDFLIB nodes to DOT label names.
    dict_rdf2_dot = {}

    # This returns the DOT label of a RDFLIB, and creates a new one if necessary.
    def _rdf_node_to_dot_label(x):
        try:
            return dict_rdf2_dot[x]
        except KeyError:
            nodelabel = "nd_%d" % len(dict_rdf2_dot)
            dict_rdf2_dot[x] = nodelabel
            return nodelabel

    # The input is any Python object.
    # This returns a simple object which can be transformed into a string.
    # If the input is a container, it returns a HTML table.
    def _format_element_aux(val, depth=0):
        if val is None:
            return ""

        try:
            int(val)
            return val
        except:
            pass

        try:
            float(val)
            return val
        except:
            pass

        if isinstance(val, dict):
            sub_table = ""
            # TODO: Consider using six.iteritems.
            for sub_key, sub_val in val.items():
                sub_td = _format_pair(sub_key, sub_val, depth + 1)
                if sub_td:
                    sub_table += "<tr>%s</tr>" % sub_td
            return "<table border='0'>%s</table>" % sub_table

        # Note: Recursive list are not very visible.
        if isinstance(val, (list, tuple)):
            # If this is an empty list or tuple.
            if not val:
                # return "(Empty)"
                # Empty set character in UTF8
                return "{" + "&#x2205;" + "}"
            if depth % 2 == 0:
                sub_table = ""
                for sub_element in val:
                    sub_td = _format_element(sub_element, depth + 1)
                    sub_table += "<tr>%s</tr>" % sub_td
                return "<table border='0'>%s</table>" % sub_table
            else:
                sub_table = ""
                for sub_element in val:
                    sub_td = _format_element(sub_element, depth + 1)
                    sub_table += sub_td
                return "<table border='0'><tr>%s</tr></table>" % sub_table

        try:
            decod_val = json.loads(val)
            return _format_element_aux(decod_val, depth + 1)

        except ValueError:
            # It is a string which cannot be converted to json.
            val = lib_util.html_escape(val)
            return _str_with_br(val)
        except TypeError:
            # "Expected a string or buffer"
            # It is not a string, so it could be a datetime.datetime
            val = lib_util.html_escape(str(val))
            return _str_with_br(val)
        return "_format_element failure"

    def _format_element(val, depth=0):
        if lib_kbase.IsLink(val):
            val_title = "_format_element " + external_url_to_title(val)
            val_title_ul = _dot_ul(val_title)
            return "<td align='left' balign='left' border='0' href='%s'>%s</td>" % (val, val_title_ul)

        res_str = _format_element_aux(val, depth)
        return "<td align='left' balign='left' border='0'>%s</td>" % res_str

    # Prints a key-value pair as two TD tags, to go in an HTML table.
    def _format_pair(key, val, depth=0):
        col_first = "<td align='left' valign='top' border='0'>%s</td>" % _dot_bold(key)
        col_second = _format_element(val, depth+1)
        return col_first + col_second

    # Display in the DOT node the list of its literal properties.
    def FieldsToHtmlVertical(grph, the_fields):
        props = {}
        idx = 0
        # TODO: The sort must put at first, some specific keys.
        # For example, sources_top/nmap_run.py, the port number as an int (Not a string)
        # Also, filenames, case-sensitive or not.
        for key, val in sorted(the_fields):
            # This should come first, but it does not so we prefix with "----". Hack !
            if key == pc.property_information:
                # Completely left-aligned. Col span is 2, approximate ratio.
                val = _str_with_br(val, 2)
                curr_td = "<td align='left' balign='left' colspan='2'>%s</td>" % val
            elif is_flat_property(key) :
                url_txt = lib_naming.ParseEntityUri(val)[0]
                split_txt = _str_with_br(url_txt, 2)
                # The text of the link must be underlined.
                curr_td = '<td href="%s" align="left" colspan="2">%s</td>' % (val, _dot_ul(split_txt))
            else:
                key_qname = lib_kbase.qname(key, grph)
                # This assumes: type(val) == 'rdflib.term.Literal'
                # sys.stderr.write("FORMAT ELEMENT: %s\n" %(dir(val)))
                if lib_kbase.IsLiteral(val):
                    curr_td = _format_pair(key_qname, val.value)
                else:
                    curr_td = _format_pair(key_qname, val)

            props[idx] = curr_td
            idx += 1
        return props

    # This lists the labels of objects which appear in the blocks,
    # and point to the name of records.
    dict_collapsed_object_labels_to_subject_labels = {}

    # This contains, for each node (subject), the related node (object) linked
    # to it with a property to be displayed in tables instead of individual nodes.
    dict_props_collapsed_subjects_to_object_lists = {}

    for collaps_prop_obj in collapsed_properties:
        # TODO: Les arguments CGI de l'URL ils servent peut-etre a trier.
        # Donc on doit les garder pour trier une fois qu'on a rassemble.
        collaps_prop_nam = lib_exports.PropToShortPropNam(collaps_prop_obj)
        dict_props_collapsed_subjects_to_object_lists[collaps_prop_nam] = collections.defaultdict(list)

    logfil.write(lib_util.TimeStamp() + " Rdf2Dot: First pass\n")

    def collapsed_label(collaps_prop_nam, subj_nam):
        """New intermediary node created."""
        assert collaps_prop_nam.find("#") < 0
        return "R_" + collaps_prop_nam + "_" + subj_nam

    # Called mainly from entity.py. If S points vers O, transforms "O" => "R_S:O"
    # Accordingly we create an edge: "S" => "R_S"
    def subj_nam_from_collapsed(collaps_prop_nam, subj_nam):
        #sys.stderr.write("ADDING1 subj_nam=%s collaps_prop_nam=%s\n" % (subj_nam,collaps_prop_nam))
        collapsed_subj_nam = dict_collapsed_object_labels_to_subject_labels[subj_nam][collaps_prop_nam]
        #sys.stderr.write("ADDING2 subj_nam=%s collaps_prop_nam=%s\n" % (subj_nam,collaps_prop_nam))
        new_subj_nam = collapsed_label(collaps_prop_nam, collapsed_subj_nam) + ":" + subj_nam
        #sys.stderr.write("ADDED collapsed_subj_nam=%s new_subj_nam=%s collaps_prop_nam=%s\n" % (collapsed_subj_nam,new_subj_nam,collaps_prop_nam))
        return new_subj_nam

    # This is sorted so the result is deterministic. Very small performance impact.
    # Any order will do as long as the result is always the same for the same URL, if the content is identical.
    sortedGrph = sorted(grph)

    # TODO: Loop only on the "collapsed" properties, the ones whose objects must be displayed
    # in tables, instead of links  - if only they have a single subject. Otherwise it cannot work.
    for subj, prop, obj in sortedGrph:

        # Objects linked with these properties, are listed in a table, instead of distinct nodes in a graph.
        if prop in collapsed_properties:
            # TODO: We lose the property, unfortunately. Should make a map: subject => prop => object ?
            subj_nam = _rdf_node_to_dot_label(subj)

            prop_nam = lib_exports.PropToShortPropNam(prop)
            dict_props_collapsed_subjects_to_object_lists[prop_nam][subj].append(obj)

            # Maybe we already entered it: Not a problem.
            obj_nam = _rdf_node_to_dot_label(obj)

            # collapsed_properties can contain only properties which define a tree,
            # as visibly the "object" nodes can have one ancestor only.
            try:
                # TODO: We should check if a node appears in two tables,
                # associated to two properties and/or two parent node.
                dict_collapsed_object_labels_to_subject_labels[obj_nam][prop_nam] = subj_nam
            except KeyError:
                dict_collapsed_object_labels_to_subject_labels[obj_nam] = dict()
                dict_collapsed_object_labels_to_subject_labels[obj_nam][prop_nam] = subj_nam

    # For getting the node of an object, as it might be in a table.
    def RdfNodeToDotLabelExtended(obj, prop):
        obj_nam = _rdf_node_to_dot_label(obj)

        try:
            dict_of_props = dict_collapsed_object_labels_to_subject_labels[obj_nam]
        except KeyError:
            # sys.stderr.write("RdfNodeToDotLabelExtended prop_nam=%s obj_nam=%s\n"%(prop_nam,obj_nam) )
            return obj_nam

        # Let's hope there is only one collapsed property for this node. Otherwise, it means
        # that this node would be displayed in two different tables. It happened...
        if not prop is None:
            prop_nam = lib_exports.PropToShortPropNam(prop)
            try:
                # Maybe this property is not collapsed.
                subj_nam = dict_of_props[prop_nam]
            except KeyError:
                prop = None

        # Maybe the property is not known, if the node is the subject.
        # Or the property is not collapsed.
        if prop is None:
            # In Python3, keys() is an iterable. No need to create a list.
            for sub_prop_nam in dict_of_props.keys():
                break
            # First property available.
            subj_nam = dict_of_props[sub_prop_nam]

        new_obj_nam = collapsed_label(sub_prop_nam, subj_nam) + ":" + obj_nam
        return new_obj_nam

    # Now we know that we have seen all nodes in a collapsed property.
    for subj, prop, obj in sortedGrph:
        if prop in collapsed_properties:
            continue

        # Maybe the subject node belongs to a table, but the property is not known.
        subj_nam = RdfNodeToDotLabelExtended(subj, None)
        if lib_kbase.IsLink(obj):

            prp_col = lib_properties.prop_color(prop)

            # TODO: REMOVE THIS HARDCODE, GENERALIZE THIS TO ALL COMMUTATIVE PROPERTIES,
            # TODO: PROPERTIES WHOSE TRIPLES ARE MERGED WHEN SIMULTANEOUSLY: (Subj,Prop,Obj) and (Obj,Prop,Subj).
            # TODO: WHEN THIS HAPPENS, THE ARROW MUST BE BIDIRECTIONAL. Commutative triples have bidirectional arrows.
            # TODO: Look for "commutative_property" and lib_properties.add_property_metadata_to_graph()
            # TODO: At the moment, only one property can be bidirectional: property_socket_end
            # if prop == pc.property_socket_end:
            if prop in commutative_properties:
                # BEWARE, MAYBE THIS IS A PORT INTO A TABLE. SO IT HAS TO BE PREFIXED BY THE RECORD NAME.
                obj_nam = RdfNodeToDotLabelExtended(obj, prop)
                if (obj, prop, subj) in grph :
                    if subj_nam < obj_nam:
                        stream.write(
                            _pattern_edge_bidirect
                            % (subj_nam, obj_nam, prp_col, lib_kbase.qname(prop, grph)))
                else:
                    # One connection only: We cannot see the other.
                    stream.write(
                        _pattern_edge_oriented
                        % (subj_nam, obj_nam, prp_col, lib_kbase.qname(prop, grph)))
            elif prop in [pc.property_rdf_data_nolist1, pc.property_rdf_data_nolist2, pc.property_rdf_data_nolist3]:
                # HTML and images urls can be "flattened" because the nodes have no descendants.
                # Do not create a node for this.
                # MIME links displayed in the same column as sub-directory.
                # Also, it might be enough to test if the object has the form "entity.py" because it has no descendant.
                # TODO: CGIPROP: Can it have several html or sub-rdf ?? It is necessary !
                fields_set[subj].append((prop, obj))
            else:
                obj_nam = RdfNodeToDotLabelExtended(obj, prop)
                # If subj_nam is in a list of dict_collapsed_subjects_to_object_lists,
                # one must add at front, the record name, i.e. its subj_nam + "_table_rdf_data:".
                try:
                    # Syntax with colon required by DOT.
                    prop_nam = lib_exports.PropToShortPropNam(prop)
                    subj_nam = subj_nam_from_collapsed(prop_nam, subj_nam)
                except KeyError:
                    # sys.stderr.write("PASS subj_nam=%s obj_nam=%s\n"%(subj_nam,obj_nam))
                    pass

                stream.write(_pattern_edge_oriented % (subj_nam, obj_nam, prp_col, lib_kbase.qname(prop, grph)))
        elif obj == None:
            # No element created in nodes[]
            fields_set[subj].append((prop, "Null"))
        else:
            # For Literals. No element created in nodes[]
            # Literals can be processed according to their type.
            # Some specific properties cannot have children so they can be stored as literals?
            fields_set[subj].append((prop, obj))

    logfil.write(lib_util.TimeStamp() + " Rdf2Dot: Replacing vectors.\n")
    logfil.write(lib_util.TimeStamp() + " Rdf2Dot: Number of collapsed properties=%d.\n" % len(collapsed_properties))

    # Now, replaces each vector by a single object containg a HTML table.
    # TODO: Unfortunately, the prop is lost, which implies that all children are mixed together.

    def _process_collapsed_properties(prop_nam):
        dict_collapsed_subjects_to_object_lists = dict_props_collapsed_subjects_to_object_lists[prop_nam]
        logfil.write(lib_util.TimeStamp()+" Rdf2Dot: dict_collapsed_subjects_to_object_lists=%d.\n"
                     % len(dict_collapsed_subjects_to_object_lists))

        for subj_url, nod_lst in six.iteritems(dict_collapsed_subjects_to_object_lists):
            subj_nam = _rdf_node_to_dot_label(subj_url)

            subj_nam_tab = collapsed_label(prop_nam, subj_nam)
            try:
                # TODO: This logic adds an extra level of node: Try to flatten the tree.
                subj_nam = subj_nam_from_collapsed(prop_nam, subj_nam)
            except KeyError:
                pass

            # This points from the subject to the table containing the objects.
            # TODO: This color should be a parameter.
            stream.write(_pattern_edge_oriented % (subj_nam, subj_nam_tab, "GREEN", prop_nam))

            lab_text, subj_entity_graphic_class, entity_id = lib_naming.ParseEntityUri(subj_url)

            # At the moment, two passes are necessary:
            # * A first pass to create the total list of fields, because they might be a bit different
            #   from one record to the other. The column names of these fields get an unique index number
            #   and can therefore be sorted.
            # * A second pass uses these result, to display the lines.
            #
            # This could be faster by assuming that the first ten or twenty columns have all the fields.
            # We could then start the second pass, and if an undetected column is found,
            # then restart from the beginning, as it is done now.

            # Unique columns of the descendant of this subject.
            raw_fields_keys = set()
            for obj in nod_lst:
                # One table per node.
                raw_fields_keys.update(fld[0] for fld in fields_set[obj])

            # sys.stderr.write("raw_fields_keys BEFORE =%s\n" % str(raw_fields_keys) )

            # Mandatory properties must come at the beginning of the columns of the header, with first indices.
            fields_keys_ordered = []
            for fld_priority in _flat_properties_list:
                try:
                    # Must always be appended. BUT IF THERE IS NO html_data, IS IT WORTH ?
                    # If the property is never used, exception then next property.
                    raw_fields_keys.remove(fld_priority)
                    fields_keys_ordered.append(fld_priority)
                except KeyError:
                    pass

            # This one is always removed because its content is concatenated at the first column.
            for fld_to_remove in [pc.property_information]:
                try:
                    raw_fields_keys.remove(fld_to_remove)
                except KeyError:
                    pass

            # Appends rest of properties which are the column names, alphabetically sorted.
            fields_keys = fields_keys_ordered + sorted(raw_fields_keys)

            # This assumes that the header columns are sorted by alphabetical order.
            key_indices = {name_key: index_key for (index_key, name_key) in enumerate(fields_keys, 1)}

            number_keys = len(key_indices)+1

            # Apparently, no embedded tables.
            dict_html_lines = dict()
            for obj_uri in nod_lst:
                # One table per node.
                sub_obj_id = _rdf_node_to_dot_label(obj_uri)

                # Beware "\L" which should not be replaced by "<TABLE>" but this is not the right place.
                sub_nod_uri = obj_uri.replace('&', '&amp;')

                try:
                    sub_obj_nam, sub_entity_graphic_class, sub_entity_id = lib_naming.ParseEntityUriShort(obj_uri)
                except UnicodeEncodeError:
                    WARNING("UnicodeEncodeError error:%s", obj_uri)
                    sub_obj_nam, sub_entity_graphic_class, sub_entity_id = ("Utf err 1", "Utf err 2", "Utf err 3")

                # sys.stderr.write("sub_entity_graphic_class=%s\n"%sub_entity_graphic_class)

                # If this is a script, always displayed on white, even if related to a specific entity.
                # THIS IS REALLY A SHAME BECAUSE WE JUST NEED THE ORIGINAL PROPERTY.
                if obj_uri.find("entity.py") < 0:
                    obj_color = "#FFFFFF"
                else:
                    obj_color = lib_patterns.EntityClassToColor(sub_entity_graphic_class)
                # This lighter cololor for the first column.
                obj_color_light = lib_patterns.ColorLighter(obj_color)

                # Some colors a bit clearer ? Or take the original color of the class ?
                td_bgcolor_plain = '<td BGCOLOR="%s" ' % obj_color
                td_bgcolor_light = '<td BGCOLOR="%s" ' % obj_color_light
                td_bgcolor = td_bgcolor_plain

                # Some columns might not have a value. The first column is for the key.
                html_columns = [td_bgcolor + " ></td>"] * number_keys

                # Just used for the vertical order of lines, one line per object.
                concatenated_info_values = ""

                for key, val in fields_set[obj_uri]:
                    # TODO: This property is by default the sorting key:
                    # TODO: This can be a parameter for lists of classes <MY_Class>
                    # TODO: ... by adding triplets of the form: (<MY_Class>, sorting_key, pc.property_information)
                    if key == pc.property_information:
                        # This can be a short string only.
                        # Instead of concatenation, consider a list, or use an unique delimiter.
                        concatenated_info_values += val
                        # If there is a key, it overrides
                        sub_entity_id = "NOT_" + "PLAINTEXTONLY" # val
                        continue

                    # TODO: This is hard-coded.
                    if is_flat_property(key) :
                        # In fact, it might also be an internal URL with "entity.py"
                        if lib_kbase.IsLiteral(val):
                            if isinstance(val.value, (list, tuple)):
                                str_html = _format_element_aux(val.value)
                                tmp_cell = td_bgcolor + 'align="left">%s</td>' % str_html
                            else:
                                tmp_cell = td_bgcolor + 'align="left">%s</td>' % val.value
                        else:
                            # This displays objects in a table: The top-level object must be
                            # in the same host, so there is no need to display a long label.
                            val_title = lib_naming.ParseEntityUriShort(val)[0]

                            assert isinstance(val_title, (six.text_type, six.binary_type))

                            # This could probably be replaced by "str"
                            # There might be non-ascii characters such as accents etc...
                            try:
                                val_title.encode('ascii')
                            except UnicodeEncodeError:
                                val_title = "Not ascii"

                            val_title_ul = _dot_ul(val_title)
                            tmp_cell = td_bgcolor + 'href="%s" align="left" >%s</td>' % (val, val_title_ul)
                    else:
                        try:
                            float(val)
                            tmp_cell = td_bgcolor + 'align="right">%s</td>' % val
                        except:
                            # Wraps the string if too long. Can happen only with a literal.
                            tmp_cell = td_bgcolor + 'align="left">%s</td>' % _str_with_br(val)

                    idx_key = key_indices[key]
                    html_columns[idx_key] = tmp_cell

                if concatenated_info_values:
                    title_key = concatenated_info_values
                else:
                    title_key = sub_obj_nam

                # Maybe the first column is a literal, and not an object ?
                if sub_entity_id != "PLAINTEXTONLY":
                    # TODO: WE SHOULD PROBABLY ESCAPE HERE TOO.
                    # For example, this displays the column labelled with pc.property_information
                    html_columns[0] = td_bgcolor_light + 'port="%s" href="%s" align="LEFT" >%s</td>' % (sub_obj_id, sub_nod_uri, title_key)
                else:
                    sys.stderr.write("sub_entity_id=%s\n" % sub_entity_id)
                    sys.stderr.write("sub_nod_uri=%s\n" % sub_nod_uri)
                    sub_nod_uri = lib_util.html_escape(sub_nod_uri)
                    # For example, this displays the title of another table: Typically sub-scripts.
                    # The title itself is not an URL.
                    html_columns[0] = td_bgcolor_light + 'port="%s" align="LEFT" >%s</td>' % (sub_obj_id, sub_nod_uri)

                # concatenated_info_values

                # Several scripts might have the same help text, so add a number.
                # "Title" => "Title"
                # "Title" => "Title/2"
                # "Title" => "Title/3" etc...
                # Beware that it is quadratic with the number of scripts with identical info.
                title_idx = 2
                title_key_uniq = title_key
                while title_key_uniq in dict_html_lines:
                    title_key_uniq = "%s/%d" % (title_key, title_idx)
                    title_idx += 1

                # TODO: The sorting order is based on these strings but should rather be based on the content.
                # TODO: For example, "(TUT_UnixProcess) Handle=10" comes before "(TUT_UnixProcess) Handle=2".
                # TODO: This is later sorted by the function lib_util.natural_sort_list.
                # TODO: Or: title_key_uniq should rather be replaced by the list of properties, for example.
                # TODO: By clicking on the column names, we could change the order.
                # TODO: Another possibility is to have a "key" metadata which would replace title_key_uniq.
                dict_html_lines[title_key_uniq] = "".join(html_columns)

            # Replace the first column by more useful information.
            num_nod_lst = len(nod_lst)

            # WBEM and WMI classes have the syntax: "ns1/ns2/ns3:class" and the class it self can have base classes.
            # Survol classes have the syntax: "dir/dir/dir/class": This considers that namespaces are not really
            # necessary and can be replaced by classes. Also, there is a one-to-one match between the class inheritance
            # tree and its directory.
            # If Survol had to be started from scratch, there would be one Python class per survol class,
            # and they would be stored in the top dir "root/cimv2" ... it is not too late !
            #
            # This strips the upper directories: "mysql/instance" or "oracle/table", if this is a Survol class
            elt_nam = sub_entity_graphic_class.split("/")[-1]
            # This strips the namespace: "root/cimv2:CIM_LogicalElement", if this is a WBEM or WMI class.
            elt_nam = elt_nam.split(":")[-1]
            if not elt_nam:
                # TODO: This is not the right criteria. Must select if we are listing scripts.
                elt_nam = "script"

            elt_nam_plural = lib_grammar.ToPlural(elt_nam, num_nod_lst)
            txt_elements = "%d %s" % (num_nod_lst, elt_nam_plural)
            header = '<td border="1">' + _dot_bold(txt_elements) + "</td>"

            # TODO: Replace each column name with a link which sorts the line based on this column.
            # The order of columns could be specified with an extra cgi argument with the columns names.
            for key in fields_keys:
                column_title = lib_kbase.qname(key, grph)
                column_title = column_title.replace("_"," ").capitalize()
                header += "<td border='1'>" + _dot_bold(column_title) + "</td>"
            # With an empty key, it comes first when sorting.
            dict_html_lines[""] = header

            # MAYBE SHOULD BE DONE TWICE !!!!! SEE ALSO ELSEWHERE !!!!
            subj_url_clean = subj_url.replace('&', '&amp;')

            # BEWARE: The shape and the color of this HTML table is from the subjects,
            # because the elements can be of different classes, even if the share the same predicate.
            # TODO: Each row should have its own color according to its class.
            num_fields = len(fields_keys)+1

            # The rows of this HTML table could belong to different classes:
            # What the shared is the predicate. Hence, the predicate, property name is used as a title.
            prop_nam_plural = lib_grammar.ToPlural(prop_nam, None)
            help_text = "List of " + prop_nam_plural + " in " + lab_text

            # TODO: The title and the content are not necessarily of the same class.
            # lab_text_with_br is the first line of the table containing nodes linked with the
            # same property. Unfortunately we have lost this property.
            lab_text = _truncate_in_space(lab_text, 30)
            lab_text_with_br = _str_with_br(lab_text)
            lab_text_with_br += ": " + prop_nam

            # No object with this script.
            if entity_id == "PLAINTEXTONLY":
                subj_url_clean = ""

            # This color is the table's contour.
            lib_patterns.WritePatterned(
                stream,
                subj_entity_graphic_class,
                subj_nam_tab,
                help_text,
                '"#000000"',
                subj_url_clean,
                num_fields,
                lab_text_with_br,
                dict_html_lines)

            # TODO: Sometimes, the same value is repeated in contiguous celles of the sames columns.
            # TODO: This could be avoided with the character '"': One just need to compare the values
            # TODO: ... consecutive cells of the same column.
            # TODO: One can even do that if the first N words of a following cell are identical.

    if collapsed_properties :
        for collapsed_prop in collapsed_properties:
            collapsed_prop_nam = lib_exports.PropToShortPropNam(collapsed_prop)
            _process_collapsed_properties(collapsed_prop_nam)

    logfil.write(lib_util.TimeStamp() + " Rdf2Dot: Display remaining nodes. dict_rdf2_dot=%d\n" % len(dict_rdf2_dot))

    # Now, display the normal nodes, which are not displayed in tables.
    for obj_rdf_node, obj_label in six.iteritems(dict_rdf2_dot):
        # TODO: Avoids this lookup.
        if obj_label in dict_collapsed_object_labels_to_subject_labels :
            continue

        obj_props_as_html = FieldsToHtmlVertical(grph, fields_set[obj_rdf_node])

        labHRef = obj_rdf_node.replace('&', '&amp;')

        try:
            # TODO: The chain is already encoded for HTML, so the parsing is different
            # TODO: ... of an URL already encoded. They are quoted then unquoted.
            lab_text, obj_entity_graph_class, entity_id = lib_naming.ParseEntityUri(
                lib_util.urllib_unquote(obj_rdf_node))
        except UnicodeEncodeError:
            WARNING("UnicodeEncodeError error:%s", obj_rdf_node)

        # WritePatterned receives an list of strings similar to "<td>jhh</td><td>jhh</td><td>jhh</td>"
        # This function adds <tr> and </tr> on both sides.
        # This avoids concatenations.

        # Ampersand are intentionally doubled, because later on they are replaced twice.
        # That is, interpreted twice as HTML entities.
        # This might be temporary until we replace CGI arguments by genuine WMI Monikers.
        lab_text_no_amp = lab_text.replace("&amp;amp;", " ")
        lab_text_no_amp = lab_text_no_amp.strip()
        lab_text_clean = _str_with_br(lab_text_no_amp)
        # Two columns because it encompasses the key and the value.

        if obj_entity_graph_class:
            help_text = lab_text_no_amp

            if not help_text:
                help_text = "Top-level script"
            # This condition is for WMI and WBEM where the name of the node is also a class or a namespace.
            # This is a bit convoluted, and just for nicer display.
            # "root/cimv2 (WBEM subclasses) at http://vps516494.ovh.net:5988 is a root/cimv2:"
            # "wmi_namespace is a wmi_namespace"
            elif not lab_text_no_amp.startswith(obj_entity_graph_class.replace(":", " ")):
                if obj_entity_graph_class:
                    # "is a" or "is an"
                    the_article = lib_grammar.IndefiniteArticle(obj_entity_graph_class)
                    help_text += " is %s %s" % (the_article, obj_entity_graph_class)
        else:
            if lab_text_clean.startswith("http"):
                help_text = "External URL " + lab_text_no_amp
            else:
                help_text = "Script " + lab_text_no_amp

        # This color is the object's contour.
        lib_patterns.WritePatterned(
            stream,
            obj_entity_graph_class,
            obj_label,
            help_text,
            '"#000000"',
            labHRef,
            2,
            lab_text_clean,
            obj_props_as_html)

    logfil.write(lib_util.TimeStamp() + " Rdf2Dot: Leaving\n")
    stream.write("}\n")


def copy_to_output_destination(logfil, svg_out_filnam, out_dest):
    """Copies a file to standard output."""

    # TODO: On Linux, consider splice.
    # See lib_kbase.triplestore_to_stream_xml for a similar situation.

    logfil.write(lib_util.TimeStamp() + " Output without conversion: %s\n" % svg_out_filnam)
    infil = open(svg_out_filnam, 'rb')
    str_in_read = infil.read()
    try:
        nb_out = out_dest.write(str_in_read)
    except TypeError as exc:
        # This happens when:
        # Python 2 and wsgiref.simple_server: unicode argument expected, got 'str'
        # Python 3 and wsgiref.simple_server: string argument expected, got 'bytes'
        nb_out = out_dest.write(str_in_read.decode('latin1'))

    logfil.write(lib_util.TimeStamp() + " End of output without conversion: %s chars\n" % str(nb_out))
    infil.close()


# TODO: Consider using the Python module pygraphviz: Small speedup probably.
# But the priority is to avoid graphes which are too long to route.
# TODO: Consider using the Python module pydot,
# but anyway it needs to have graphviz already installed.
# Also, creating an intermediary files helps debugging.
def _dot_to_svg(dot_filnam_after, logfil, viztype, out_dest):
    DEBUG("viztype=%s", viztype)
    tmp_svg_fil = lib_util.TmpFile("survol_graph_to_svg", "svg")
    svg_out_filnam = tmp_svg_fil.Name
    # dot -Kneato

    # Dot/Graphviz no longer changes PATH at installation. It must be done BEFORE.
    dot_path = "dot"

    if lib_util.isPlatformLinux:
        # TODO: This is arbitrary because old Graphviz version.
        # TODO: Take the fonts from html_exports.css
        dot_fonts = [
                    # "-Gfontpath=/usr/share/fonts/dejavu",
                    "-Gfontpath=/usr/share/fonts",
                    "-Gfontnames=svg",
                    "-Nfontname=DejaVuSans.ttf",
                    "-Efontname=DejaVuSans.ttf"]
    else:
        dot_fonts = []

    # Old versions of dot need the layout on the command line.
    # This is maybe a bit faster than os.open because no shell and direct write to the output.
    svg_command = [dot_path, "-K", viztype, "-Tsvg", dot_filnam_after, "-o", svg_out_filnam,
                   "-v", "-Goverlap=false"] + dot_fonts
    str_command = " ".join(svg_command)
    logfil.write(TimeStamp()+" svg_command=" + str_command + "\n")

    try:
        ret = subprocess.call(svg_command, stdout=logfil, stderr=logfil, shell=False)
    except Exception as exc:
        raise Exception("ERROR:%s raised:%s" % (str_command, str(exc)))
    logfil.write(TimeStamp()+" Process ret=%d\n" % ret)

    if not os.path.isfile(svg_out_filnam):
        raise Exception("SVG file " + svg_out_filnam + " could not be created.")

    # TODO: If there is an error, we should write it as an HTML page.
    # On the other hand it is impossible to pipe the output because it would assume a SVG document.

    # https://stackoverflow.com/questions/5667576/can-i-set-the-html-title-of-a-pdf-file-served-by-my-apache-web-server
    dict_http_properties = [("Content-Disposition", 'inline; filename="Survol_Download"')]

    logfil.write(lib_util.TimeStamp() + " Writing SVG header\n")
    lib_util.WrtHeader("image/svg+xml", dict_http_properties)

    # Here, we are sure that the output file is closed.
    copy_to_output_destination(logfil, svg_out_filnam, out_dest)


def _font_string():
    # fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
    # stream.write("node [shape=plaintext fontpath=\"/usr/share/fonts\" fontname=\"DejaVuSans\" ]")

    if lib_util.isPlatformWindows:
        return 'fontname="DejaVu Sans"'
    else:
        # fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
        return 'fontpath="/usr/share/fonts" fontname="DejaVuSans"'


def write_dot_header(page_title, layout_style, stream, grph):
    # Some cleanup.
    page_title_clean = page_title.strip()
    # Escape double-quotes.
    page_title_clean = page_title_clean.replace("\n", " ").replace("\"", "\\\"")
    # Title embedded in the page.
    stream.write('digraph "' + page_title_clean + '" { \n')

    # CSS style-sheet should be in the top-level directory ?
    # Not implemented in 2010: http://graphviz.org/bugs/b1874.html
    # Add a CSS-like "class" attribute
    # stream.write(' stylesheet = "rdfmon.css" \n')

    # Maybe the layout is forced.
    # dot - "hierarchical" or layered drawings of directed graphs. This is the default tool to use if edges have directionality.
    # neato - "spring model'' layouts.  This is the default tool to use if the graph is not too large (about 100 nodes) and you don't know anything else about it. Neato attempts to minimize a global energy function, which is equivalent to statistical multi-dimensional scaling.
    # fdp - "spring model'' layouts similar to those of neato, but does this by reducing forces rather than working with energy.
    # sfdp - multiscale version of fdp for the layout of large graphs.
    # twopi - radial layouts, after Graham Wills 97. Nodes are placed on concentric circles depending their distance from a given root node.
    # circo - circular layout, after Six and Tollis 99, Kauffman and Wiese 02. This is suitable for certain diagrams of multiple cyclic structures, such as certain telecommunications networks.
    # This is a style more than a dot layout.
    # sys.stderr.write("Lay=%s\n" % (layout_style) )
    if layout_style == "LAYOUT_RECT":
        dot_layout = "dot"
        # Very long lists: Or very flat tree.
        stream.write(" splines=\"ortho\"; \n")
        stream.write(" rankdir=\"LR\"; \n")
    elif layout_style == "LAYOUT_RECT_RL":
        dot_layout = "dot"
        # Very long lists: Or very flat tree.
        stream.write(" splines=\"ortho\"; \n")
        stream.write(" rankdir=\"RL\"; \n")
    elif layout_style == "LAYOUT_RECT_TB":
        dot_layout = "dot"
        # Very long lists: Or very flat tree.
        stream.write(" splines=\"ortho\"; \n")
        # stream.write(" rank=\"source\"; \n")
        stream.write(" rankdir=\"TB\"; \n")
    elif layout_style == "LAYOUT_TWOPI":
        # Used specifically for file/file_stat.py : The subdirectories
        # are vertically stacked.
        dot_layout = "twopi"
        stream.write(" rankdir=\"LR\"; \n")
    elif layout_style == "LAYOUT_SPLINE":
        # Win32_Services, many interconnections.
        dot_layout = "fdp"
        # stream.write(" splines=\"curved\"; \n") # About as fast as straight lines
        stream.write(" splines=\"spline\"; \n") # Slower than "curved" but acceptable.
        stream.write(" rankdir=\"LR\"; \n")
        # stream.write(" splines=\"compound\"; \n") ### TRES LENT
    else:
        dot_layout = "fdp" # Faster than "dot"
        # TODO: Maybe we could use the number of elements len(grph)  ?
        stream.write(" rankdir=\"LR\"; \n")
    stream.write(" layout=\"" + dot_layout + "\"; \n")

    # TODO: Take the font from the CSS html_exports.css
    # Example on Windows: stream.write(" node [ fontname=\"DejaVu Sans\" ] ; \n")
    stream.write(" node [ %s ] ; \n" % _font_string())
    return dot_layout


def GraphToSvg(
        page_title, error_msg, is_sub_server, parameters, grph, parameterized_links, top_url,
        layout_style, collapsed_properties, commutative_properties):
    """This transforms a RDF triplestore into a temporary DOT file, which is
    transformed by GraphViz into a SVG file sent to the HTTP browser. """
    tmp_log_fil = lib_util.TmpFile("survol_graph_to_svg", "log")
    try:
        logfil = open(tmp_log_fil.Name, "w")
    except Exception as exc:
        ERROR("_graph_to_svg caught %s when opening:%s", str(exc), tmp_log_fil.Name)
        raise Exception("_graph_to_svg caught %s when opening:%s\n" % (str(exc), tmp_log_fil.Name))

    logfil.write("Starting logging\n")

    tmp_dot_fil = lib_util.TmpFile("survol_graph_to_svg", "dot")
    dot_filnam_after = tmp_dot_fil.Name
    rdfoutfil = open(dot_filnam_after, "w")
    logfil.write(lib_util.TimeStamp() + " Created " + dot_filnam_after + "\n")

    dot_layout = write_dot_header(page_title, layout_style, rdfoutfil, grph)
    _write_dot_legend(page_title, top_url, error_msg, is_sub_server,
                      parameters, parameterized_links, rdfoutfil, grph)
    logfil.write(lib_util.TimeStamp() + " Legend written\n")
    Rdf2Dot(grph, logfil, rdfoutfil, collapsed_properties, commutative_properties)
    logfil.write(lib_util.TimeStamp() + " About to close dot file\n")

    # BEWARE: Do this because the file is about to be reopened from another process.
    rdfoutfil.flush()
    os.fsync(rdfoutfil.fileno())
    rdfoutfil.close()

    out_dest = lib_util.get_default_output_destination()

    _dot_to_svg(dot_filnam_after, logfil, dot_layout, out_dest)
    logfil.write(lib_util.TimeStamp() + " closing log file\n")
    logfil.close()


def _url_to_svg(url):
    """This is very primitive and maybe should be replaced by a standard function,
    but lib_util.EncodeUri() replaces "too much", and SVG urls cannot encode an ampersand...
    The problems comes from "&mode=edit" or "&mode=html" etc..."""

    # TODO: If we can fix this, then "xid" can be replaced by "entity_type/entity_id"
    return url.replace("&", "&amp;amp;")


def _dot_bold(a_str):
    if not a_str: return ""
    return "<b>%s</b>" % a_str


def _dot_ul(a_str):
    if not a_str: return ""
    return "<u>%s</u>" % a_str


# Do not italicize empty string otherwise "Error: syntax error in line 1 ... <i></i> ..."
def _dot_it(a_str):
    if not a_str: return ""
    return "<i>%s</i>" % a_str


# To display long strings in HTML-like labels, when Graphviz creates SVG.
_max_html_title_len_per_col = 40

# This is a HTML-like tag for Graphviz only.
_with_br_delim = '<BR ALIGN="LEFT" />'


def _str_with_br(a_raw_str, colspan=1):
    """Inserts "<BR/>" in a string so it can be displayed in a HTML label.
    Beware that it is not really HTML, but only an HTML-like subset.
    See https://www.graphviz.org/doc/info/shapes.html#html """

    # First thing: Cleanup possible HTML tags, otherwise Graphviz stops.
    aStr = a_raw_str.replace("<", "&lt;").replace(">", "&gt;")

    len_str = len(aStr)
    max_html_title_len = colspan * _max_html_title_len_per_col
    if len_str < max_html_title_len:
        return aStr

    splt = aStr.split(" ")
    tot_len = 0
    resu = ""
    curr_line = ""
    for curr_str in splt:
        subLen = len(curr_str)
        if tot_len + subLen < max_html_title_len:
            curr_line += " " + curr_str
            tot_len += subLen
            continue
        if resu:
            resu += _with_br_delim
        resu += curr_line
        curr_line = curr_str
        tot_len = subLen

    if curr_line:
        if resu != "":
            resu += _with_br_delim
        resu += curr_line
    return resu


def _write_dot_legend(page_title, top_url, err_msg, is_sub_server, parameters, parameterized_links, stream, grph):
    """In SVG/Graphiz documents, this writes the little rectangle which contains various information."""

    # This allows to enter directly the URL parameters, so we can access directly an object.
    # This will allow to choose the entity type, and each parameter of the URL (Taken
    # from the ontology). It also edits the parameters of the current URL.
    # TODO: MUST FINISH THIS.
    #def UrlDirectAccess():
    #    return "direct_access.py"

    # This adds links which can display the same content in a different output format.
    def legend_add_alternate_display_links(stream):
        # So we can change parameters of this CGI script.
        url_html = lib_exports.ModedUrl("html")
        url_json = lib_exports.ModedUrl("json")
        url_rdf = lib_exports.ModedUrl("rdf")
        urlD3 = lib_exports.UrlToMergeD3()

        # Stupid replacement of dot: "\\" transformed into "\"
        # Fix for : "http://rchateau-hp:8000/survol/class_wmi.py?xid=\\machine\root\CIMV2%3ACIM_Directory.&mode=html"
        def url_for_dot(md_url):
            md_url = md_url.replace("\\\\", "\\\\\\")
            return _url_to_svg(md_url)

        stream.write("<tr><td colspan='4'><table border='0'>")
        stream.write(
            "<tr>"
            "<td>(</td>"
            "<td align='left' href='" + url_for_dot(url_html) + "'>" + _dot_ul("HTML") + "</td>"
            "<td>,</td>"
            "<td align='left' href='" + url_for_dot(url_json) + "'>" + _dot_ul("JSON") + "</td>"
            "<td>,</td>"
            "<td align='left' href='" + url_for_dot(url_rdf) + "'>" + _dot_ul("RDF") + "</td>"
            "<td>,</td>"
            "<td align='left' href='" + url_for_dot(urlD3) + "'>" + _dot_ul("D3") + "</td>"
            "<td>)</td></tr>"
        )
        stream.write("</table></td></tr>")

    def legend_add_parameters_links(stream, parameters, parameterized_links):
        """This displays the parameters of the URL and a link allowing to edit them.
        It assumes that it writes in the middle of a table with two columns."""

        if parameters :
            url_edit = lib_exports.ModedUrl("edit")
            url_edit_replaced = _url_to_svg(url_edit)
            stream.write("<tr><td colspan='4' href='" + url_edit_replaced + "' align='left'>"
                         + _dot_bold(_dot_ul("Edit script parameters")) + "</td></tr>")

            arguments = cgi.FieldStorage()
            for key_param, val_param in parameters.items():
                try:
                    actual_param = arguments[key_param].value
                except KeyError:
                    actual_param = val_param
                stream.write('<tr><td colspan="2">%s:</td><td colspan="2">%s</td></tr>'
                             % (key_param, _dot_it(actual_param)))

        # We want to display links associated to the parameters.
        # The use case is "Prev/Next" when paging between many values.
        # This could be nicely modelled by just specifying special set of values,
        # and the links would be calculated here.
        # For example: { "next" : { "index": curr + 80 }, "prev" : { "index": curr - 80 } }
        # This simplifies the edition in Json.
        # It might also simplify formatting.
        # There will be a similar piece of code in Javascript and plain HTML:
        # (1) The calling script provides the values to CgiEnv.
        # (2) A method in CgiEnv calculates the URLS and returns a map
        # of { "label":"urls" }

        for url_label in parameterized_links:
            param_url = parameterized_links[url_label]
            stream.write("<tr><td colspan='4' href='" + param_url + "' align='left'>"
                         + _dot_bold(_dot_ul(url_label)) + "</td></tr>")

    def legend_footer():

        url_help = _url_to_svg(lib_exports.UrlWWW("help.htm"))

        stream.write("<tr>")
        stream.write('<td align="left" href="' + top_url + '">' + _dot_bold(_dot_ul("Home")) + '</td>')
        urlEdtConfiguration = lib_util.uriRoot + "/edit_configuration.py"
        stream.write("<td href='" + urlEdtConfiguration + "' align='left'>" + _dot_bold(_dot_ul("Setup")) + "</td>")
        urlEdtCredentials = lib_util.uriRoot + "/edit_credentials.py"
        stream.write("<td href='" + urlEdtCredentials +"' align='left'>" + _dot_bold(_dot_ul("Credentials")) + "</td>")
        stream.write("<td href='" + url_help +"' align='left'>" + _dot_bold(_dot_ul("Help")) + "</td>")
        stream.write("</tr>")


    # stream.write("node [shape=plaintext fontname=\"DejaVu Sans\" ]")
    # fontname: "DejaVuSans.ttf" resolved to: (PangoCairoFcFont) "DejaVu Sans, Book" /usr/share/fonts/dejavu/DejaVuSans.ttf
    # stream.write("node [shape=plaintext fontpath=\"/usr/share/fonts\" fontname=\"DejaVuSans\" ]")
    stream.write("node [shape=plaintext %s ]" % _font_string())

    # The first line is a title, the rest, more explanations.
    # The first line also must be wrapped if it is too long.
    # TODO: This logic should be factorised because it seems to be used when merging ?

    page_title_first, page_title_rest = lib_util.SplitTextTitleRest(page_title)

    page_title_first_wrapped = _str_with_br(page_title_first, 2)
    page_title_rest_wrapped = _str_with_br(page_title_rest, 2)
    page_title_full = _dot_bold(page_title_first_wrapped) + _with_br_delim + page_title_rest_wrapped

    stream.write("""
  subgraph cluster_01 {
    subgraph_cluster_key [shape=none, label=<<table border="1" cellpadding="0" cellspacing="0" cellborder="0">""")

    stream.write("<tr><td colspan='4'>" + page_title_full + "</td></tr>" )
    legend_add_alternate_display_links(stream)
    legend_add_parameters_links(stream,parameters,parameterized_links)

    legend_footer()

    # The error message could be None or an empty string.
    if err_msg:
        full_err_msg = _dot_bold("Error: ") + err_msg
        stream.write('<tr><td align="left" balign="left" colspan="2">%s</td></tr>' % _str_with_br(full_err_msg, 2))

    if is_sub_server:
        url_stop = lib_exports.ModedUrl("stop")
        url_stop_replaced = _url_to_svg(url_stop)
        stream.write('<tr><td colspan="2" href="' + url_stop_replaced + '">' + _dot_ul("Stop subserver") + '</td></tr>')
        # TODO: Add an URL for subservers management, instead of simply "stop"
        # Maybe "mode=ctrl".This will list the feeders with their entity_id.
        # So they can be selectively stopped.

    stream.write("""
      </table>>]
  }
     """)
