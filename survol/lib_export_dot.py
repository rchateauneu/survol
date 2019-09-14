import sys
import json
import cgi
import re
import collections

import lib_exports
import lib_kbase
import lib_naming
import lib_patterns
import lib_grammar

import lib_util
from lib_util import TimeStamp

import lib_properties
from lib_properties import pc


################################################################################

# TODO: Take the colors from the CSS html_exports.css
# TODO: Add a tool tip. Also, adapt the color to the context.
pattEdgeOrien = "\t%s -> %s [ color=%s, label=< <font point-size='10' " + \
    "color='#336633'>%s</font> > ] ;\n"
pattEdgeBiDir = "\t%s -> %s [ dir=both color=%s, label=< <font point-size='10' " + \
    "color='#336633'>%s</font> > ] ;\n"


# Returns a string for an URL which might be different from "entity.py" etc...
# TODO: Ca serait mieux de passer le texte avec la property.
def ExternalToTitle(extUrl):
    # Depending on where we come from, "%2F" instead of "/" ... ugly.
    # BEWARE: This is completely experimental. See if "Yawn" is actually used.
    if re.match( ".*/yawn/.*", extUrl ) or re.match( ".*%2Fyawn%2F.*", extUrl ):
        return "Yawn"

    pyNamMtch = re.match( ".*/([^.]+).py.*", extUrl )
    if pyNamMtch:
        pyNam = pyNamMtch.group(1)

        # After all, the script might be entity
        if pyNam == "entity":
            (objNam, entity_graphic_class, entity_id) = lib_naming.ParseEntityUri( extUrl )
            return objNam

        try:
            # TODO: See lib_naming.scripts_to_titles
            basNamToTxt = {
                "objtypes_wbem" : "Subtypes", # This key is duplicated !!!!
                "file_directory" : "Subdir",
                "file_to_mime" : "MIME",
                "objtypes_wmi" : "WMI tree",
                "objtypes_wbem" : "WBEM hier.",
                "class_type_all" : "Cross class",
                "dir_to_html" : "DIR"
            }
            return basNamToTxt[pyNam]
        except:
            return pyNam.replace("_"," ").capitalize()
    else:
        # sys.stderr.write("extUrl=%s\n"%extUrl)
        return "Literal:"+extUrl

# These properties must have their object displayed not as a separated node,
# but as a link displayed with a string, a plain HREF.
FlatPropertiesList = [ pc.property_rdf_data_nolist1, pc.property_rdf_data_nolist2, pc.property_rdf_data_nolist3 ]
def IsFlatProperty(key):
    return key in FlatPropertiesList


# Used for transforming into SVG format.
# If from entity.py, CollapsedProps = pc.property_directory,pc.property_script
def Rdf2Dot( grph, logfil, stream, CollapsedProperties ):
    fieldsSet = collections.defaultdict(list)

    # This maps RDFLIB nodes to DOT label names.
    dictRdf2Dot = {}

    # This returns the DOT label of a RDFLIB, and creates a new one if necessary.
    def RdfNodeToDotLabel(x):
        try:
            return dictRdf2Dot[x]
        except KeyError:
            nodelabel = "nd_%d" % len(dictRdf2Dot)
            dictRdf2Dot[x] = nodelabel
            return nodelabel

    # The input is any Python object.
    # This returns a simple object which can be transformed into a string.
    # If the input is a container, it returns a HTML table.
    def FormatElementAux(val,depth=0):
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

        if isinstance(val,dict):
            subTable = ""
            # TODO: Consider using six.iteritems.
            for subKey,subVal in val.items():
                subTd = FormatPair(subKey,subVal, depth + 1)
                if subTd:
                    subTable += "<tr>%s</tr>" % subTd
            return "<table border='0'>%s</table>" % subTable

        # Note: Recursive list are not very visible.
        if isinstance(val, ( list, tuple ) ):
            # If this is an empty list or tuple.
            if not val:
                # return "(Empty)"
                # Empty set character in UTF8
                return "{"+"&#x2205;"+"}"
            if depth % 2 == 0:
                subTable = ""
                for subElement in val:
                    subTd = FormatElement( subElement, depth + 1 )
                    subTable += "<tr>%s</tr>" % subTd
                return "<table border='0'>%s</table>" % subTable
            else:
                subTable = ""
                for subElement in val:
                    subTd = FormatElement( subElement, depth + 1 )
                    subTable += subTd
                return "<table border='0'><tr>%s</tr></table>" % subTable

        try:
            decodVal = json.loads(val)
            return FormatElementAux(decodVal, depth + 1)

        except ValueError:
            # It is a string which cannot be converted to json.
            val = cgi.escape(val)
            return lib_exports.StrWithBr(val)
        except TypeError:
            # "Expected a string or buffer"
            # It is not a string, so it could be a datetime.datetime
            val = cgi.escape(str(val))
            return lib_exports.StrWithBr(val)
        return "FormatElement failure"

    def FormatElement(val,depth=0):
        if lib_kbase.IsLink(val):
            valTitle = "FormatElement "+ExternalToTitle(val)
            valTitleUL = lib_exports.DotUL(valTitle)
            return "<td align='left' balign='left' border='0' href='%s'>%s</td>" % (val,valTitleUL )

        resStr = FormatElementAux(val,depth)
        return "<td align='left' balign='left' border='0'>%s</td>" % resStr


    # Prints a key-value pair as two TD tags, to go in an HTML table.
    def FormatPair(key,val,depth=0):
        colFirst = "<td align='left' valign='top' border='0'>%s</td>" % lib_exports.DotBold(key)
        colSecond = FormatElement(val,depth+1)
        return colFirst + colSecond

    # Display in the DOT node the list of its literal properties.
    def FieldsToHtmlVertical(grph, the_fields):
        props = {}
        idx = 0
        # TODO: The sort must put at first, some specific keys.
        # For example, sources_top/nmap_run.py, the port number as an int (Not a string)
        # Also, filenames, case-sensitive or not.
        for ( key, val ) in sorted(the_fields):
            # This should come first, but it does not so we prefix with "----". Hack !
            if key == pc.property_information:
                # Completely left-aligned. Col span is 2, approximate ratio.
                val = lib_exports.StrWithBr(val,2)
                currTd = "<td align='left' balign='left' colspan='2'>%s</td>" % val
            elif IsFlatProperty(key) :
                urlTxt = lib_naming.ParseEntityUri(val)[0]
                splitTxt = lib_exports.StrWithBr(urlTxt, 2)
                # The text of the link must be underlined.
                currTd = '<td href="%s" align="left" colspan="2">%s</td>' % ( val, lib_exports.DotUL(splitTxt) )
            else:
                key_qname = lib_kbase.qname( key, grph )
                # This assumes: type(val) == 'rdflib.term.Literal'
                # sys.stderr.write("FORMAT ELEMENT: %s\n" %(dir(val)))
                if lib_kbase.IsLiteral(val):
                    currTd = FormatPair( key_qname, val.value )
                else:
                    currTd = FormatPair( key_qname, val )

            props[idx] = currTd
            idx += 1
        return props

    # Ca liste les labels des objects qui apparaissent dans les blocs,
    # et pointent vers le nom du record.
    dictCollapsedObjectLabelsToSubjectLabels = {}

    # This contains, for each node (subject), the related node (object) linked
    # to it with a property to be displayed in tables instead of individual nodes.
    dictPropsCollapsedSubjectsToObjectLists = {}

    for collapsPropObj in CollapsedProperties:
        collapsPropNam = lib_exports.PropToShortPropNam(collapsPropObj)
        dictPropsCollapsedSubjectsToObjectLists[collapsPropNam] = collections.defaultdict(list)


    # TODO: (TRANSLATE THIS) Une premiere passe pour batir l'arbre d'une certaine propriete.
    # Si pas un DAG, tant pis, ca fera un lien en plus.
    # ON voulait batir des records, mais les nodes dans un record ne peuvent pas
    # avoir un URL: Donc ca va pas evidemment.
    # HTML-LIKE Labels avec PORT et PORTPOS.
    # CA VA AUSSI SIMPLIFIER L'AFFICHAGE DES TRUCS ENORMES: Modules, Fichiers etc...
    # Et on pourra trier car il y a un ordre.
    # Donc ca doit etre facile d'ajouter des proprietes affichees comme ca.

    logfil.write( TimeStamp()+" Rdf2Dot: First pass\n" )

    # New intermediary node created.
    def CollapsedLabel(collapsPropNam,subjNam):
        assert collapsPropNam.find("#") < 0
        return "R_" + collapsPropNam + "_" + subjNam

    # Called mainly from entity.py. If S points vers O, transforms "O" => "R_S:O"
    # Accordingly we create an edge: "S" => "R_S"
    def SubjNamFromCollapsed(collapsPropNam,subjNam):
        #sys.stderr.write("ADDING1 subjNam=%s collapsPropNam=%s\n" % (subjNam,collapsPropNam))
        collapsedSubjNam = dictCollapsedObjectLabelsToSubjectLabels[ subjNam ][collapsPropNam]
        #sys.stderr.write("ADDING2 subjNam=%s collapsPropNam=%s\n" % (subjNam,collapsPropNam))
        newSubjNam = CollapsedLabel( collapsPropNam, collapsedSubjNam ) + ":" + subjNam
        #sys.stderr.write("ADDED collapsedSubjNam=%s newSubjNam=%s collapsPropNam=%s\n" % (collapsedSubjNam,newSubjNam,collapsPropNam))
        return newSubjNam

    # This is sorted so the result is deterministic. Very small performance impact.
    # Any order will do as long as the result is always the same.
    sortedGrph = sorted(grph)

    # TODO: Loop only on the "collapsed" properties, the ones whose objects must be displayed
    # in tables, instead of links  - if only they have a single subject. Otherwise it cannot work.
    for subj, prop, obj in sortedGrph:

        # Objects linked with these properties, are listed in a table, instead of distinct nodes in a graph.
        if prop in CollapsedProperties:
            # TODO: We lose the property, unfortunately. Should make a map: subject => prop => object ?
            subjNam = RdfNodeToDotLabel(subj)

            propNam = lib_exports.PropToShortPropNam(prop)
            dictPropsCollapsedSubjectsToObjectLists[ propNam ][ subj ].append( obj )

            # Maybe we already entered it: Not a problem.
            objNam = RdfNodeToDotLabel(obj)

            # CollapsedProperties can contain only properties which define a tree,
            # as visibly the "object" nodes can have one ancestor only.
            try:
                # TODO: We should check if a node appears in two tables,
                # associated to two properties and/or two parent node.
                dictCollapsedObjectLabelsToSubjectLabels[ objNam ][ propNam ] = subjNam
            except KeyError:
                dictCollapsedObjectLabelsToSubjectLabels[ objNam ] = dict()
                dictCollapsedObjectLabelsToSubjectLabels[ objNam ][ propNam ] = subjNam

    # For getting the node of an object, as it might be in a table.
    def RdfNodeToDotLabelExtended(obj,prop):
        objNam = RdfNodeToDotLabel(obj)

        try:
            dictOfProps = dictCollapsedObjectLabelsToSubjectLabels[ objNam ]
        except KeyError:
            # sys.stderr.write("RdfNodeToDotLabelExtended propNam=%s objNam=%s\n"%(propNam,objNam) )
            return objNam

        # Let's hope there is only one collapsed property for this node. Otherwise, it means
        # that this node would be displayed in two different tables. It happened...
        if not prop is None:
            propNam = lib_exports.PropToShortPropNam(prop)
            try:
                # Maybe this property is not collapsed.
                subjNam = dictOfProps[propNam]
            except KeyError:
                prop = None

        # Maybe the property is not known, if the node is the subject.
        # Or the property is not collapsed.
        if prop is None:
            # In Python3, keys() is an iterable. No need to create a list.
            for propNam in dictOfProps.keys():
                break
            # First property available.
            subjNam = dictOfProps[propNam]

        newObjNam = CollapsedLabel( propNam, subjNam ) + ":" + objNam
        return newObjNam

    # Now we know that we have seen all nodes in a collapsed property.
    for subj, prop, obj in sortedGrph:
        if prop in CollapsedProperties:
            continue

        # Maybe the subject node belongs to a table, but the property is not known.
        subjNam = RdfNodeToDotLabelExtended(subj,None)
        if lib_kbase.IsLink(obj):

            prp_col = lib_properties.prop_color(prop)

            # TODO: GENERALIZE THIS TO ALL COMMUTATIVE PROPERTIES.
            # THAT IS: PROPERTIES WHOSE TRIPLES ARE MERGED WHEN
            # WE HAVE AT THE SAME TIME: (Subj,Prop,Obj) and (Obj,Prop,Subj).
            # WHEN THIS HAPPENS, THE ARROW MUST BE BIDIRECTIONAL.
            # TODO: All commutative relation have bidirectional arrows.
            # At the moment, only one property can be bidirectional.
            if prop == pc.property_socket_end:

                # BEWARE, MAYBE THIS IS A PORT INTO A TABLE. SO IT HAS TO BE PREFIXED BY THE RECORD NAME.
                objNam = RdfNodeToDotLabelExtended(obj,prop)
                if ( obj, prop, subj ) in grph :
                    if subjNam < objNam:
                        stream.write(pattEdgeBiDir % (subjNam, objNam, prp_col, lib_kbase.qname(prop, grph)))
                else:
                    # One connection only: We cannot see the other.
                    stream.write(pattEdgeOrien % (subjNam, objNam, prp_col, lib_kbase.qname(prop, grph)))
            elif prop in [ pc.property_rdf_data_nolist1 , pc.property_rdf_data_nolist2, pc.property_rdf_data_nolist3 ]:
                # TODO: Il suffit de tester si obj est un url de la forme "entity.py" ???
                # HTML and images urls can be "flattened" because the nodes have no descendants.
                # Do not create a node for this.
                # MIME links displayed in the same column as sub-directory.
                # Also, it might be enough to test if the object has the form "entity.py" because it has no descendant.
                # TODO: CGIPROP: Can it have several html or sub-rdf ?? It is necessary !
                fieldsSet[subj].append( ( prop, obj ) )
            else:
                objNam = RdfNodeToDotLabelExtended(obj,prop)
                # C est la que si subjNam est dans une liste de dictCollapsedSubjectsToObjectLists,
                # il faut rajouter devant, le nom du record, c est a dire SON subjNam + "_table_rdf_data:".
                try:
                    # Syntax with colon required by DOT.
                    propNam = lib_exports.PropToShortPropNam(prop)
                    subjNam = SubjNamFromCollapsed(propNam,subjNam)
                except KeyError:
                    # sys.stderr.write("PASS subjNam=%s objNam=%s\n"%(subjNam,objNam))
                    pass

                stream.write(pattEdgeOrien % (subjNam, objNam, prp_col, lib_kbase.qname(prop, grph)))
        elif obj == None:
            # No element created in nodes[]
            fieldsSet[subj].append((prop, "Null" ))
        else:
            # For Literals. No element created in nodes[]
            # Literals can be processed according to their type.
            # Some specific properties cannot have children so they can be stored as literals?
            # Les proprietes comme "pid", on devrait plutot afficher le lien vers le process, dans la table ???
            # Les URLs de certaines proprietes sont affichees en colonnes.
            # Ou bien pour ces proprietes, on recree un entity.py ??

            fieldsSet[subj].append( ( prop, obj ) )

    logfil.write( TimeStamp()+" Rdf2Dot: Replacing vectors: CollapsedProperties=%d.\n" % ( len( CollapsedProperties ) ) )

    # Now, replaces each vector by a single object containg a HTML table.
    # TODO: Unfortunately, the prop is lost, which implies that all children are mixed together.

    def ProcessCollapsedProperties( propNam ):
        dictCollapsedSubjectsToObjectLists = dictPropsCollapsedSubjectsToObjectLists[propNam]
        logfil.write( TimeStamp()+" Rdf2Dot: dictCollapsedSubjectsToObjectLists=%d.\n" % ( len( dictCollapsedSubjectsToObjectLists ) ) )

        for subjUrl, nodLst in lib_util.six_iteritems(dictCollapsedSubjectsToObjectLists):
            subjNam = RdfNodeToDotLabel(subjUrl)

            subjNamTab = CollapsedLabel(propNam,subjNam)
            try:
                # TODO: This logic adds an extra level of node: Try to flatten the tree.
                subjNam = SubjNamFromCollapsed(propNam,subjNam)
            except KeyError:
                pass

            # This points from the subject to the table containing the objects.
            # TODO: This color should be a parameter.
            stream.write(pattEdgeOrien % (subjNam, subjNamTab, "GREEN", propNam))

            ( labText, subjEntityGraphicClass, entity_id) = lib_naming.ParseEntityUri( subjUrl )

            # At the moment, two passes are necessary:
            # * A first pass to create the compte list of fields, because they might be a bit different
            #   from one record to the other. The column names pf these fields get an unique index number
            #   and can therefore be sorted.
            # * A second pass uses these result, to display the lines.
            #
            # This could be faster by assuming that the first ten columns have all the fields.
            # We could then start the second pass, and if an undetected column is found,
            # then restart from scratch.

            # Unique columns of the descendant of this subject.
            rawFieldsKeys = set()
            for obj in nodLst:
                # One table per node.
                rawFieldsKeys.update( fld[0] for fld in fieldsSet[obj] )

            # sys.stderr.write("rawFieldsKeys BEFORE =%s\n" % str(rawFieldsKeys) )

            # Mandatory properties must come at the beginning of the columns of the header, with first indices.
            # BUG: Si on retire html de cette liste alors qu il y a des valeurs, colonnes absentes.
            # S il y a du html ou du RDF, on veut que ca vienne en premier.
            fieldsKeysOrdered = []
            for fldPriority in FlatPropertiesList:
                try:
                    # Must always be appended. BUT IF THERE IS NO html_data, IS IT WORTH ?
                    # TODO: Remove if not HTML and no sub-rdf. CGIPROP

                    # If the property is never used, exception then next property.
                    rawFieldsKeys.remove( fldPriority )
                    fieldsKeysOrdered.append( fldPriority )
                except KeyError:
                    pass

            # This one is always removed because its content is concatenated at the first column.
            for fldToRemove in [ pc.property_information ]:
                try:
                    rawFieldsKeys.remove( fldToRemove )
                except KeyError:
                    pass

            # Appends rest of properties, sorted.
            fieldsKeys = fieldsKeysOrdered + sorted(rawFieldsKeys)

            # sys.stderr.write("fieldsKeys=%s\n" % str(fieldsKeys) )

            # This assumes that the header columns are sorted.
            keyIndices = { nameKey:indexKey for (indexKey,nameKey) in enumerate(fieldsKeys,1) }

            numberKeys = len(keyIndices)+1

            # Apparently, no embedded tables.
            dictHtmlLines = dict()
            for objUri in nodLst:
                # One table per node.
                subObjId = RdfNodeToDotLabel(objUri)

                # Beware "\L" which should not be replaced by "<TABLE>" but this is not the right place.
                subNodUri = objUri.replace('&','&amp;')

                try:
                    (subObjNam, subEntityGraphicClass, subEntityId) = lib_naming.ParseEntityUriShort( objUri )
                except UnicodeEncodeError:
                    WARNING( "UnicodeEncodeError error:%s", objUri )
                    (subObjNam, subEntityGraphicClass, subEntityId) = ("Utf problem1","Utf problem2","Utf problem3")

                # sys.stderr.write("subEntityGraphicClass=%s\n"%subEntityGraphicClass)

                # If this is a script, always displayed on white, even if related to a specific entity.
                # THIS IS REALLY A SHAME BECAUSE WE JUST NEED THE ORIGINAL PROPERTY.
                if objUri.find("entity.py") < 0:
                    objColor = "#FFFFFF"
                else:
                    objColor = lib_patterns.EntityClassToColor(subEntityGraphicClass)
                # This lighter cololor for the first column.
                objColorLight = lib_patterns.ColorLighter(objColor)

                # Some colors a bit clearer ? Or take the original color of the class ?
                td_bgcolor_plain = '<td BGCOLOR="%s" ' % objColor
                td_bgcolor_light = '<td BGCOLOR="%s" ' % objColorLight
                td_bgcolor = td_bgcolor_plain

                # Some columns might not have a value. The first column is for the key.
                columns = [ td_bgcolor + " ></td>" ] * numberKeys

                # Just used for the vertical order of lines, one line per object.
                title = ""

                # TODO: CGIPROP. This is not a dict, the same key can appear several times ?
                for ( key, val ) in fieldsSet[objUri]:
                    if key == pc.property_information:
                        # This can be a short string only.
                        title += val
                        continue

                    # TODO: This is hard-coded.
                    if IsFlatProperty(key) :

                        # In fact, it might also be an internal URL with "entity.py"
                        if lib_kbase.IsLiteral(val):
                            if isinstance( val.value, (list, tuple )):
                                strHtml = FormatElementAux(val.value)
                                DEBUG("val.value=%s",strHtml)
                                tmpCell = td_bgcolor + 'align="left">%s</td>' % strHtml
                            else:
                                tmpCell = td_bgcolor + 'align="left">%s</td>' % val.value
                        else:
                            # This displays objects in a table: The top-level object must be
                            # in the same host, so there is no need to display a long label.
                            valTitle = lib_naming.ParseEntityUriShort( val )[0]
                            assert isinstance(valTitle, lib_util.six_text_type)

                            # There might be non-ascii characters such as accents etc...
                            try:
                                valTitle.encode('ascii')
                            except UnicodeEncodeError:
                                valTitle = "Not ascii"

                            valTitleUL = lib_exports.DotUL(valTitle)
                            tmpCell = td_bgcolor + 'href="%s" align="left" >%s</td>' % ( val , valTitleUL )

                    else:
                        try:
                            float(val)
                            tmpCell = td_bgcolor + 'align="right">%s</td>' % val
                        except:
                            # Wraps the string if too long. Can happen only with a literal.
                            tmpCell = td_bgcolor + 'align="left">%s</td>' % lib_exports.StrWithBr(val)

                    idxKey = keyIndices[key]
                    columns[ idxKey ] = tmpCell

                if title:
                    title_key = title
                else:
                    title_key = subObjNam

                # Maybe the first column is a literal ?
                if subEntityId != "PLAINTEXTONLY":
                    # WE SHOULD PROBABLY ESCAPE HERE TOO.
                    columns[0] = td_bgcolor_light + 'port="%s" href="%s" align="LEFT" >%s</td>' % ( subObjId, subNodUri, title_key )
                else:
                    subNodUri = cgi.escape(subNodUri)
                    columns[0] = td_bgcolor_light + 'port="%s" align="LEFT" >%s</td>' % ( subObjId, subNodUri )

                # Several scripts might have the same help text, so add a number.
                # "Title" => "Title"
                # "Title" => "Title/2"
                # "Title" => "Title/3" etc...
                # Beware that it is quadratic with the number of scripts with identical info.
                title_idx = 2
                title_uniq = title_key
                while title_uniq in dictHtmlLines:
                    title_uniq = "%s/%d" % ( title_key, title_idx )
                    title_idx += 1

                # TODO: L'ordre est base sur les chaines mais devrait etre base sur le contenu. Exemple:
                # TODO: "(TUT_UnixProcess) Handle=10" vient avant "(TUT_UnixProcess) Handle=2"
                # TODO: title_uniq devrait etre plutot la liste des proprietes.
                # TODO: By clicking on the column names, we could change the order.
                dictHtmlLines[ title_uniq ] = "".join( columns )

            # Replace the first column by more useful information.
            numNodLst = len(nodLst)

            # WBEM and WMI classes have the syntax: "ns1/ns2/ns3:class" and the class it self can have base classes.
            # Survol classes have the syntax: "dir/dir/dir/class": This considers that namespaces are not really
            # necessary and can be replaced by classes. Also, there is a one-to-one match between the class inheritance
            # tree and its directory.
            # If Survol had to be started from scratch, there would be one Python class per survol class,
            # and they would be stored in the top dir "root/cimv2" ... it is not too late !
            #
            # This strips the upper directories: "mysql/instance" or "oracle/table", if this is a Survol class
            eltNam = subEntityGraphicClass.split("/")[-1]
            # This strips the namespace: "root/cimv2:CIM_LogicalElement", if this is a WBEM or WMI class.
            eltNam = eltNam.split(":")[-1]
            if not eltNam:
                # TODO: This is not the right criteria. Must select if we are listing scripts.
                eltNam = "script"

            eltNamPlural = lib_grammar.ToPlural(eltNam,numNodLst)
            txtElements = "%d %s" % ( numNodLst, eltNamPlural )
            header = '<td border="1">' + lib_exports.DotBold(txtElements) + "</td>"

            # TODO: Replace each column name with a link which sorts the line based on this column.
            # The order of columns could be specified with an extra cgi argument with the columns names.
            for key in fieldsKeys:
                columnTitle = lib_kbase.qname(key,grph)
                columnTitle = columnTitle.replace("_"," ").capitalize()
                header += "<td border='1'>" + lib_exports.DotBold( columnTitle ) + "</td>"
            # With an empty key, it comes first when sorting.
            dictHtmlLines[""] = header

            # MAYBE SHOULD BE DONE TWICE !!!!! SEE ALSO ELSEWHERE !!!!
            subjUrlClean = subjUrl.replace('&','&amp;')

            # BEWARE: The shape and the color of this HTML table is from the subjects,
            # because the elements can be of different classes, even if the share the same predicate.
            # TODO: Each row should have its own color according to its class.
            numFields = len(fieldsKeys)+1

            # The rows of this HTML table could belong to different classes:
            # What the shared is the predicate. Hence, the predicate, property name is used as a title.
            propNamPlural = lib_grammar.ToPlural(propNam,None)
            helpText = "List of " + propNamPlural + " in " + labText

            # TODO: Le title and the content are not necessarily of the same class.
            # labTextWithBr is the first line of the table containing nodes linked with the
            # same property. Unfortunately we have lost this property.
            labText = lib_exports.TruncateInSpace(labText,30)
            labTextWithBr = lib_exports.StrWithBr( labText )
            labTextWithBr += ": "+propNam

            if entity_id == "PLAINTEXTONLY":
                subjUrlClean = ""

            # This color is the table's contour.
            lib_patterns.WritePatterned( stream, subjEntityGraphicClass, subjNamTab, helpText, '"#000000"', subjUrlClean, numFields, labTextWithBr, dictHtmlLines )

            # TODO: Sometimes, the same value is repeated in contiguous celles of the sames columns.
            # TODO: This could be avoided with the character '"': One just need to compare the values
            # TODO: ... consecutive cells of the same column.
            # TODO: One can even do that if the first N words of a following cell are identical.

    if CollapsedProperties :
        for collapsedProp in CollapsedProperties:
            collapsedPropNam = lib_exports.PropToShortPropNam(collapsedProp)
            ProcessCollapsedProperties(collapsedPropNam)

    logfil.write( TimeStamp()+" Rdf2Dot: Display remaining nodes. dictRdf2Dot=%d\n" % len(dictRdf2Dot) )

    # Now, display the normal nodes, which are not displayed in tables.
    for objRdfNode, objLabel in lib_util.six_iteritems(dictRdf2Dot):
        # TODO: Avoids this lookup.
        if objLabel in dictCollapsedObjectLabelsToSubjectLabels :
            continue

        objPropsAsHtml = FieldsToHtmlVertical( grph, fieldsSet[objRdfNode])

        labHRef = objRdfNode.replace('&','&amp;')

        try:
            # TODO: The chain is already encoded for HTML, so the parsing is different
            # TODO: ... of an URL already encoded. They are quoted then unquoted.
            (labText, objEntityGraphClass, entity_id) = lib_naming.ParseEntityUri( lib_util.urllib_unquote(objRdfNode) )
        except UnicodeEncodeError:
            WARNING( "UnicodeEncodeError error:%s", objRdfNode )

        # WritePatterned receives an list of strings similar to "<td>jhh</td><td>jhh</td><td>jhh</td>"
        # This function adds <tr> and </tr> on both sides.
        # This avoids concatenations.

        # Ampersand are intentionally doubled, because later on they are replaced twice.
        # That is, interpreted twice as HTML entities.
        # This might be temporary until we replace CGI arguments by genuine WMI Monikers.
        labTextNoAmp = labText.replace("&amp;amp;"," ")
        labTextNoAmp = labTextNoAmp.strip()
        labTextClean = lib_exports.StrWithBr( labTextNoAmp)
        # Two columns because it encompasses the key and the value.

        if objEntityGraphClass:
            helpText = labTextNoAmp

            if not helpText:
                helpText = "Top-level script"
            # This condition is for WMI and WBEM where the name of the node is also a class or a namespace.
            # This is a bit convoluted, and just for nicer display.
            # "root/cimv2 (WBEM subclasses) at http://vps516494.ovh.net:5988 is a root/cimv2:"
            # "wmi_namespace is a wmi_namespace"
            elif not labTextNoAmp.startswith( objEntityGraphClass.replace(":", " ") ):
                if objEntityGraphClass:
                    # "is a" or "is an"
                    theArticle = lib_grammar.IndefiniteArticle(objEntityGraphClass)
                    helpText += " is %s %s" % ( theArticle, objEntityGraphClass )
        else:
            if labTextClean.startswith("http"):
                helpText = "External URL " + labTextNoAmp
            else:
                helpText = "Script " + labTextNoAmp

        # This color is the object's contour.
        lib_patterns.WritePatterned( stream, objEntityGraphClass, objLabel, helpText, '"#000000"', labHRef, 2, labTextClean, objPropsAsHtml )

    logfil.write( TimeStamp()+" Rdf2Dot: Leaving\n" )
    stream.write("}\n")

