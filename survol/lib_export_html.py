"""
    Transforms an internal graph into a HTML page.
"""
import os
import sys
import lib_util
import lib_mime
import lib_exports
import lib_patterns
import lib_naming
import lib_kbase
import entity_dirmenu_only
from lib_properties import pc
from lib_util import WrtAsUtf
from sources_types import CIM_ComputerSystem

# TODO: Use descriptions provided by lib_bookmark.py

listPropsTdDoubleColSpan = [pc.property_information,pc.property_rdf_data_nolist2,pc.property_rdf_data_nolist1]

# This does not change the existing mode if there is one.
# Otherwise it could erase the MIME type.
def UrlInHtmlMode(anUrl):
    urlMode = lib_util.GetModeFromUrl(anUrl)
    # sys.stderr.write("UrlInHtmlMode anUrl=%s urlMode=%s\n"%(anUrl,urlMode))
    if urlMode:
        return anUrl
    else:
        return lib_util.AnyUriModed(anUrl, "html")

def ScriptInformationHtmlIterator(theCgi,gblCgiEnvList):
    """
        This displays general information about this script and the object if there is one.
    """
    DEBUG("WriteScriptInformation entity_type=%s",theCgi.m_entity_type)

    # This is already called in lib_common, when creating CgiEnv.
    # It does not matter because this is very fast.
    callingUrl = lib_util.RequestUri()
    ( entity_label, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(callingUrl,longDisplay=True)
    DEBUG("entity_label=%s entity_graphic_class=%s entity_id=%s", entity_label, entity_graphic_class, entity_id )

    # WrtAsUtf('<table class="list_of_merged_scripts">')
    yield('<table border="0">')
    if len(gblCgiEnvList):
        DEBUG("gblCgiEnvList=%s",str(gblCgiEnvList))
        # This step is dedicated to the merging of several scripts.

        yield("<tr align=left><td colspan=2 align=left><h2>Fusion of data from %d scripts</h2></td></tr>"%len(gblCgiEnvList))
        for aCgiEnv in gblCgiEnvList:
            DEBUG("aCgiEnv=%s",str(aCgiEnv))
            DEBUG("aCgiEnv.m_page_title=%s",str(aCgiEnv.m_page_title))
            DEBUG("aCgiEnv.m_calling_url=%s",str(aCgiEnv.m_calling_url))
            #(page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(aCgiEnv.m_page_title)
            page_title_first,page_title_rest = aCgiEnv.m_page_title, aCgiEnv.m_page_subtitle
            yield("<tr><td><a href='%s'>%s</td><td><i>%s</i></td></tr>"%(aCgiEnv.m_calling_url,page_title_first,page_title_rest))
    else:
        # (page_title_first,page_title_rest) = lib_util.SplitTextTitleRest(theCgi.m_page_title)
        (page_title_first,page_title_rest) = theCgi.m_page_title, theCgi.m_page_subtitle
        yield("<tr><td colspan=2><h2>%s</h2></td></tr>"%(page_title_first))
        if page_title_rest:
            yield("<tr><td colspan=2>%s</td></tr>"%(page_title_rest))

    yield('</table>')

def ObjectInformationHtmlIterator(theCgi,gblCgiEnvList):
    if theCgi.m_entity_type:
        # WrtAsUtf('m_entity_id: %s<br>'%(theCgi.m_entity_id))

        entity_module = lib_util.GetEntityModule(theCgi.m_entity_type)
        entDoc = entity_module.__doc__
        if entDoc:
            entDoc = entDoc.strip()
        else:
            entDoc = ""

        urlClass = lib_util.EntityClassUrl(theCgi.m_entity_type)
        urlClass_with_mode = UrlInHtmlMode( urlClass )

        yield('<table class="table_script_information">')
        yield(
        """
        <tr>
            <td><a href='%s'>%s</a></td>
            <td>%s</td>
        </tr>
        """
        % ( urlClass_with_mode, theCgi.m_entity_type, entDoc ))

        for dict_property_value in theCgi.m_entity_id_dict.items():
            yield("<tr><td>%s</td><td>%s</td></tr>" % dict_property_value )

        yield('</table>')


def ParametersEditionHtmlIterator(theCgi):
    """
        This displays the parameters of the script and provide an URL to edit them.
    """

    if len(theCgi.m_parameters) == 0:
        return

    import lib_edition_parameters

    formAction = os.environ['SCRIPT_NAME']

    for linHtml in lib_edition_parameters.FormEditionParameters(formAction,theCgi):
        yield linHtml

def OthersUrls(topUrl):
    if topUrl:
        topUrl_with_mode = UrlInHtmlMode( topUrl )
        yield(topUrl_with_mode,"Home")

    yield(lib_exports.ModedUrl("svg"),"SVG format","Graphviz&trade; generated")

    yield(lib_exports.ModedUrl("rdf"),"RDF format","Semantic Web, RDF-Schema / Prot&eacute;g&eacute;&trade; / Jena...")

    yield(lib_exports.UrlToMergeD3(),"D3","Javascript D3 library")

def OtherUrlsHtmlIterator(topUrl):
    """
        This displays the URL to view the same document, in other output formats.
    """

    for urlTrip in OthersUrls(topUrl):
        if len(urlTrip) == 2:
            yield('<tr><td align="left" colspan="2"><a href="%s"><b>%s</b></a></td></tr>' % urlTrip )
        else:
            yield('<tr><td class="other_urls"><a href="%s">%s</a></td><td>%s</td></tr>' % urlTrip )

def CIMUrlsHtmlIterator():
    # This callback receives a RDF property (WBEM or WMI) and a map
    # which represents the CIM links associated to the current object.
    def WMapToHtml(theMap):
        DEBUG("WMapToHtml len=%d",len(theMap))
        for urlSubj in theMap:
            (subjText, subjEntityGraphClass, subjEntityId) = lib_naming.ParseEntityUri( lib_util.urllib_unquote(urlSubj) )
            yield("<tr>")
            yield("<td valign='top'><a href='%s'>%s</a></td>"%( str(urlSubj), subjText ) )
            yield("<td>")
            yield("<table border=0>")
            for theProp, urlObj in theMap[urlSubj]:
                yield("<tr>")
                propNam = lib_exports.PropToShortPropNam(theProp)
                yield("<td><i>%s</i></td>"%propNam)
                if lib_kbase.IsLiteral(urlObj):
                    yield("<td>%s</td>"%( str(urlObj) ) )
                else:
                    (objText, objEntityGraphClass, objEntityId) = lib_naming.ParseEntityUri( lib_util.urllib_unquote(urlObj) )
                    yield("<td><a href='%s'>%s</a></td>"%( str(urlObj), objText ) )
                yield("</tr>")
            yield("</table>")
            yield("</td>")
        yield("</tr>")

    callingUrl = lib_util.RequestUri()
    ( entity_label, entity_type, entity_id ) = lib_naming.ParseEntityUri(callingUrl,longDisplay=True)
    host_wbem_wmi = lib_util.currentHostname
    nameSpace = ""

    mapWbem = CIM_ComputerSystem.AddWbemServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
    for linHtml in WMapToHtml(mapWbem):
        yield linHtml
    mapWmi = CIM_ComputerSystem.AddWmiServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
    for linHtml in WMapToHtml(mapWmi):
        yield linHtml
    mapSurvol = CIM_ComputerSystem.AddSurvolServers(host_wbem_wmi, nameSpace, entity_type, entity_id)
    for linHtml in WMapToHtml(mapSurvol):
        yield linHtml

def ScriptsTreeHtmlIterator(theCgi):
    """
        This displays the tree of accessible Python scripts for the current object.
        It is displayed as a recursive table. A similar logic is used in entity.
        (Where the tree is displayed as a tree of SVG nodes) and in index.htm
        (With a contextual menu).
    """

    # Otherwise it does not work with class_type_all.py
    if(theCgi.m_entity_type != "") and (theCgi.m_entity_id ==""):
        return

    flagVal = theCgi.GetParameters( lib_util.paramkeyShowAll )
    DEBUG("WriteScriptsTree flagVal=%s",flagVal)
    # This happens when merging scripts.
    if flagVal == "":
        flagShowAll = 0
    else:
        flagShowAll = int(flagVal)

    rootNode = None

    dictScripts = {}

    # This function is called for each script which applies to the given entity.
    # It receives a triplet: (subject,property,object) and the depth in the tree.
    # Here, this simply stores the scripts in a map, which is later used to build
    # the HTML display. The depth is not used yet.
    def CallbackGrphAdd( trpl, depthCall ):
        subj,prop,obj = trpl

        # sys.stderr.write("CallbackGrphAdd subj=%s\n"%str(subj))
        try:
            mapProps = dictScripts[subj]
            try:
                lstObjs = mapProps[prop].append(obj)
            except KeyError:
                mapProps[prop] = [obj]
        except KeyError:
            dictScripts[subj] = { prop : [obj ] }

    DEBUG("WriteScriptsTree entity_type=%s flagShowAll=%d",theCgi.m_entity_type,flagShowAll)
    entity_dirmenu_only.DirToMenu(CallbackGrphAdd,rootNode,theCgi.m_entity_type,theCgi.m_entity_id,theCgi.m_entity_host,flagShowAll)

    DEBUG("dictScripts %d",len(dictScripts))


    def DisplayLevelTable(subj,depthMenu=1):
        """
            Top-level should always be none.
            TODO: Have another version which formats all cells the same way.
            For this, have a first pass which counts, at each node, the number of sub-nodes.
            Then a second pass which uses thiese counts and the current depth,
            to calculate the rowspan and colspan of each cell.
            Although elegant, it is not garanteed to work.
        """
        yield('<table class="scripts_tree_class">')
        try:
            mapProps = dictScripts[subj]
        except KeyError:
            return

        def ExtractTitleFromMapProps(mapProps):
            if len(mapProps) != 1:
                return None
            for oneProp in mapProps:
                if oneProp != pc.property_information:
                    return None

                lstStr = mapProps[oneProp]
                if len(lstStr) != 1:
                    return None
                retStr = lstStr[0]
                if lib_kbase.IsLink( retStr ):
                    return None

                return str(retStr)

        yield('<tr class="scripts_tree_class">')
        depthMenu += 1

        subj_uniq_title = ExtractTitleFromMapProps(mapProps)

        if subj:
            subj_str = str(subj)
            yield('<td valign="top" rowspan="%d" class="scripts_tree_class">'%len(mapProps))
            if lib_kbase.IsLink( subj ):
                url_with_mode = UrlInHtmlMode( subj_str )
                if subj_uniq_title:
                    subj_uniq_title_not_none = subj_uniq_title
                else:
                    subj_uniq_title_not_none = "No title"
                yield( '<a href="' + url_with_mode + '">' + subj_uniq_title_not_none + "</a>")
            else:
                yield( subj_str )
            yield("</td>")

        if not subj_uniq_title:
            for oneProp in mapProps:
                lstObjs = mapProps[oneProp]

                yield('<td class="scripts_tree_class">')
                yield('<table class="scripts_tree_class">')
                for oneObj in lstObjs:
                    if oneObj is None:
                        continue
                    yield('<tr class="scripts_tree_class">')
                    yield('<td class="scripts_tree_class">')
                    try:
                        for linHtml in DisplayLevelTable(oneObj,depthMenu):
                            yield linHtml
                    except KeyError:
                        yield("Script error: "+str(oneObj))
                    yield('</td>')
                    yield('</tr>')
                yield('</table>')
                yield('</td>')

        yield('</tr>')
        yield( "</table>")

    for linHtml in DisplayLevelTable(None):
        yield linHtml

def WriteErrorsNoJinja(error_msg,isSubServer):
    if error_msg or isSubServer:
        yield('<table border="0">')

        if error_msg:
            yield('<tr><td bgcolor="#DDDDDD" align="center" color="#FF0000"><b></b></td></tr>')
            yield('<tr><td bgcolor="#DDDDDD"><b>ERROR MESSAGE:%s</b></td></tr>' % error_msg)

        if isSubServer:
            yield('<tr><td><a href="' + lib_exports.ModedUrl("stop") + '">Stop subserver</a></td></tr>')
        yield( " </table><br>")

# TODO: When the objects have the same column names, displaying could be optimised
# into a single table without repetition of the same titles.

def CreateObjectsList(grph):
    """
        This displays all the objects returned by this scripts.
        Other scripts are not here, so we do not have to eliminate them.
        This is therefore simpler than in the SVG (Graphviz) output,
        where all objects are mixed together.
    """

    # This groups data by subject, then predicate, then object.
    dictClassSubjPropObj = dict()

    # TODO: Group objects by type, then display the count, some info about each type etc...
    for aSubj, aPred, anObj in grph:
        # No point displaying some keys if there is no value.
        if aPred == pc.property_information :
            try:
                if str(anObj) == "":
                    continue
            # 'ascii' codec can't encode character u'\xf3' in position 17: ordinal not in range(128)
            # u'SDK de comprobaci\xf3n de Visual Studio 2012 - esn'
            except UnicodeEncodeError:
                exc = sys.exc_info()[1]
                ERROR("Exception %s",str(exc))
                continue

        subj_str = str(aSubj)
        ( subj_title, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(subj_str)

        try:
            dictSubjPropObj = dictClassSubjPropObj[entity_graphic_class]
            try:
                dictPred = dictSubjPropObj[aSubj]
                try:
                    dictPred[aPred].append(anObj)
                except KeyError:
                    # First time this object has this predicate.
                    dictPred[aPred] = [ anObj ]
            except KeyError:
                # First time we see this object.
                dictSubjPropObj[aSubj] = { aPred : [ anObj ] }
        except KeyError:
            # First object of this class.
            dictClassSubjPropObj[entity_graphic_class] = { aSubj: { aPred : [ anObj ] } }
    return dictClassSubjPropObj

def ObjectsTriplets(dictClassSubjPropObj):
    # Group objects by class.
    # Display list of classes with an index and a link to the class.

    # No need to use natural sort, because these are no filenames or strings containing numbers.
    for entity_graphic_class in sorted(dictClassSubjPropObj):
        urlClass = lib_util.EntityClassUrl(entity_graphic_class)
        urlClass_with_mode = UrlInHtmlMode( urlClass )
        dictSubjPropObj = dictClassSubjPropObj[entity_graphic_class]

        arrayGraphParams = lib_patterns.TypeToGraphParams(entity_graphic_class)
        # "Graphic_shape","Graphic_colorfill","Graphic_colorbg","Graphic_border","Graphic_is_rounded"
        colorClass = arrayGraphParams[1]

        yield( urlClass_with_mode, entity_graphic_class, colorClass, dictSubjPropObj )




def WriteAllObjectsNoJinja(dictClassSubjPropObj):
    for (urlClass_with_mode, entity_graphic_class, colorClass, dictSubjPropObj) in ObjectsTriplets(dictClassSubjPropObj):
        yield("<h3>Class <a href='%s'>%s</a></h3>"%(urlClass_with_mode,entity_graphic_class))
        yield('<table class="class_objects" bgcolor=%s>'%colorClass)
        one_class_html = "".join( DispClassObjectsNoJinja(dictSubjPropObj) )
        yield one_class_html
        yield(" </table>")

def DispClassObjectsNoJinja(dictSubjPropObj):

    # The subjects must be sorted by their title.
    lstTuplesSubjects = []
    for aSubj in dictSubjPropObj:
        subj_str = str(aSubj)
        ( subj_title, entity_graphic_class, entity_id ) = lib_naming.ParseEntityUri(subj_str)
        lstTuplesSubjects.append((aSubj,subj_str,subj_title, entity_graphic_class, entity_id))

    # Sorted by the title of the subject, which is the third value of the tuple.
    lib_util.natural_sort_list(lstTuplesSubjects,key=lambda tup: tup[2])

    # Apparently, a problem is that "%" gets transformed into an hexadecimal number, preventing decoding.
    def DesHex(theStr):
        theStr = lib_util.survol_unescape(theStr)
        return theStr.replace("%25","%").replace("%2F","/").replace("%5C","\\").replace("%3A",":")

    # Now it iterates on the sorted list.
    # This reuses all the intermediate values.
    for aSubj,subj_str,subj_title, entity_graphic_class, entity_id in lstTuplesSubjects:
        dictPred = dictSubjPropObj[aSubj]

        # Total number of lines.
        cntPreds = 0
        for aPred in dictPred:
            lstObjs = dictPred[aPred]
            cntPreds += len(lstObjs)

        mustWriteColOneSubj = True

        subj_str_with_mode = UrlInHtmlMode( subj_str )

        # The predicates, i.e. the properties associated a subject with an object,
        # must be alphabetically sorted.
        for aPred in lib_util.natural_sorted(dictPred):
            lstObjs = dictPred[aPred]

            predStr = lib_exports.AntiPredicateUri(str(aPred))
            cntObjs = len(lstObjs)
            mustWriteColOnePred = True

            # The objects must be sorted by title.
            lstTuplesObjs = []
            for anObj in lstObjs:
                obj_str = str(anObj)
                obj_str = DesHex(obj_str)
                obj_title = lib_naming.ParseEntityUri(obj_str)[0]
                lstTuplesObjs.append((anObj,obj_str,obj_title))

            # Sorted by the title of the object, which is the third value of the tuple.
            lib_util.natural_sort_list(lstTuplesObjs,key=lambda tup: tup[2])

            for anObj,obj_str,obj_title in lstTuplesObjs:

                yield( '<tr>' )

                if mustWriteColOneSubj:
                    yield(
                        '<td valign="top" rowspan="%s"><a href="%s">%s</a></td>'
                        % (str(cntPreds), subj_str_with_mode, subj_title ) )
                    mustWriteColOneSubj = False

                if mustWriteColOnePred:
                    if aPred not in listPropsTdDoubleColSpan :
                        yield( '<td valign="top" rowspan="%s">%s</td>' % (str(cntObjs), predStr) )
                    mustWriteColOnePred = False

                if aPred in listPropsTdDoubleColSpan:
                    colSpan = 2
                else:
                    colSpan = 1

                dispMimeUrls = True

                yield( '<td colspan="%d">' %(colSpan))
                if dispMimeUrls:
                    if lib_kbase.IsLink( anObj ):
                        objStrClean = lib_util.UrlNoAmp(obj_str)
                        mimeType = lib_mime.GetMimeTypeFromUrl(objStrClean)
                        if mimeType:
                            if mimeType.startswith("image/"):
                                yield(
                                    """<a href="%s"><img src="%s" alt="%s" height="42" width="42"></a>"""
                                    % (obj_str,obj_str,obj_title)
                                )
                            else:
                                yield( """<a href="%s">%s</a>""" % (obj_str,obj_title) )
                        else:
                            url_with_mode = lib_util.AnyUriModed(obj_str, "html")
                            yield( """<a href="%s">%s</a>""" % (url_with_mode,obj_title) )
                    else:
                        yield( '%s' %(obj_str))
                else:
                    if lib_kbase.IsLink( anObj ):
                        url_with_mode = UrlInHtmlMode( obj_str )
                        yield( '<a href="%s">%s</a>' % (url_with_mode,obj_title))
                    else:
                        yield( '%s' %(obj_str))

                yield( "</td>")
                yield( "</tr>")

def DisplayHtmlTextHeader(page_title):
    """
    This is the common Survol header, ideally for all HTML documents.
    """
    WrtAsUtf( """
    <head>
        <title>%s</title>
        <link rel='stylesheet' type='text/css' href=/ui/css/html_exports.css>
        <link rel='stylesheet' type='text/css' href='/survol/www/css/html_exports.css'>
        <link rel='stylesheet' type='text/css' href='../survol/www/css/html_exports.css'>
    </head>
    """ % page_title )

def DisplayHtmlTextFooter():
    """
    This is the common Survol footer.
    """

    # See lib_exports.LegendFooter, similar footer.

    # This needs a directory which depends on the HTTP hosting, such as on OVH.
    # TODO: Probably useless.
    urlIndex = lib_exports.UrlWWW("index.htm")
    urlEdtConfiguration = lib_util.uriRoot + "/www/edit_configuration.py"
    urlEdtCredentials = lib_util.uriRoot + "/www/edit_credentials.py"

    wrtFmt = """
    <br>
    <table width="100%%"><tr>
    <td><a href="%s">Survol home</a></td>
    <td><a href="%s">Configuration</a></td>
    <td><a href="%s">Credentials</a></td>
    <td align="right">&copy; <a href="http://www.primhillcomputers.com">Primhill Computers</a> 2017-2019</i></td>
    </tr></table>
    """

    wrtTxt = wrtFmt % (urlIndex,urlEdtConfiguration,urlEdtCredentials)
    yield(wrtTxt)

def Grph2HtmlNoJinja( theCgi, topUrl, error_msg, isSubServer,gblCgiEnvList):
    """
        This transforms an internal data graph into a HTML document.
    """
    page_title = theCgi.m_page_title
    grph = theCgi.m_graph

    DisplayHtmlTextHeader(page_title)

    WrtAsUtf('<body>')

    script_information = "".join( ScriptInformationHtmlIterator(theCgi,gblCgiEnvList) )
    WrtAsUtf(script_information)
    object_information = "".join( ObjectInformationHtmlIterator(theCgi,gblCgiEnvList) )
    WrtAsUtf(object_information)

    WrtAsUtf("".join( WriteErrorsNoJinja(error_msg,isSubServer) ) )

    dictClassSubjPropObj = CreateObjectsList(grph)

    WrtAsUtf("".join( WriteAllObjectsNoJinja(dictClassSubjPropObj) ) )

    parameters_edition_html = "".join( ParametersEditionHtmlIterator(theCgi) )
    if parameters_edition_html:
        WrtAsUtf("<h2>Script parameters</h2>")
        WrtAsUtf(parameters_edition_html)

    # Scripts do not apply when displaying a class.
    # TODO: When in a enumerate script such as enumerate_CIM_LogicalDisk.py,
    # it should assume the same: No id but a class.
    if(theCgi.m_entity_type == "") or (theCgi.m_entity_id!=""):
        WrtAsUtf("<h2>Related data scripts</h2>")
        WrtAsUtf("".join( ScriptsTreeHtmlIterator(theCgi) ) )

    WrtAsUtf("<h2>Other related urls</h2>")
    WrtAsUtf('<table class="other_urls">')
    WrtAsUtf("".join( OtherUrlsHtmlIterator(topUrl) ) )
    WrtAsUtf("".join( CIMUrlsHtmlIterator() ) )
    WrtAsUtf('</table>')

    htmlFooter = "".join( DisplayHtmlTextFooter() )
    WrtAsUtf(htmlFooter)

    WrtAsUtf("</body>")

    WrtAsUtf("</html> ")

def Grph2HtmlJinja( theCgi, topUrl, error_msg, isSubServer,gblCgiEnvList):
    this_dir = os.path.dirname(os.path.abspath(__file__))
    template_file_name = "www/export_html.template.htm"

    # The current URL is used to calculate the base href.
    current_uri = lib_util.RequestUri()

    parsed_url = lib_util.survol_urlparse(current_uri)
    path_url = parsed_url.path

    # Something like "/survol" or "survol/sources_types"
    url_dir = os.path.dirname(path_url)

    num_slashes = len( url_dir.split("/") ) - 2
    base_href = ( "../" * num_slashes ) + "www/"

    # Create the jinja2 environment.
    # Notice the use of trim_blocks, which greatly helps control whitespace.
    jinja2 = lib_util.GetJinja2()
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(this_dir), trim_blocks=True)
    jinja_template = jinja_env.get_template(template_file_name)

    script_information_html = "".join( ScriptInformationHtmlIterator(theCgi,gblCgiEnvList) )
    object_information_html = "".join( ObjectInformationHtmlIterator(theCgi,gblCgiEnvList) )

    errors_table_html = "".join( WriteErrorsNoJinja(error_msg,isSubServer) )

    dictClassSubjPropObj = CreateObjectsList(theCgi.m_graph)

    all_objects_list = []
    for (urlClass_with_mode, entity_graphic_class, colorClass, dictSubjPropObj) in ObjectsTriplets(dictClassSubjPropObj):
        one_class_html = "".join( DispClassObjectsNoJinja(dictSubjPropObj) )
        all_objects_list.append( (urlClass_with_mode,entity_graphic_class,colorClass,one_class_html))

    parameters_edition_html = "".join( ParametersEditionHtmlIterator(theCgi) )

    scripts_tree_html = "".join( ScriptsTreeHtmlIterator(theCgi) )

    list_other_urls = OthersUrls(topUrl)
    html_cim_urls = "".join( CIMUrlsHtmlIterator() )

    jinja_render = jinja_template.render(
        base_href=base_href,
        page_title=theCgi.m_page_title,
        script_information=script_information_html,
        object_information=object_information_html,
        errors_table_html=errors_table_html,
        all_objects_list=all_objects_list,
        parameters_edition_html=parameters_edition_html,
        scripts_tree_html=scripts_tree_html,
        list_other_urls = list(list_other_urls),
        html_cim_urls = html_cim_urls
    )
    WrtAsUtf( jinja_render )

# The list gblCgiEnvList contains a list of URL which are merged
# into the current URLs. There are displayed for informational purpose.
def Grph2Html( theCgi, topUrl, error_msg, isSubServer,gblCgiEnvList):
    lib_util.WrtHeader('text/html')
    if lib_util.GetJinja2():
        Grph2HtmlJinja( theCgi, topUrl, error_msg, isSubServer,gblCgiEnvList)
    else:
        Grph2HtmlNoJinja( theCgi, topUrl, error_msg, isSubServer,gblCgiEnvList)

################################################################################
