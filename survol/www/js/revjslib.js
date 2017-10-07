/** revlibjs.js
 * Common Javascript libraries for HTML pages.
 */

// http://stackoverflow.com/questions/470832/getting-an-absolute-url-from-a-relative-one-ie6-issue
/*
function qualifyURL(url)
{
    var a = document.createElement('a');
    a.href = url;
    return a.cloneNode(false).href;
}
*/

////////////////////////////////////////////////////////////////////////////////

function AddUrlCgiArg(urlQuery, cgiArgs )
{
	if( cgiArgs != "") {
		var ixQuest = urlQuery.indexOf("?");
		if( ixQuest >= 0 )
			urlQuery += "&";
		else
			urlQuery += "?";
		urlQuery += cgiArgs;
		}

	return urlQuery;
}

function AddUrlPrefix(urlQuery, cgiArgs )
{
	console.log("AddUrlPrefix urlQuery="+urlQuery);
	var ixPrim = window.location.hostname.indexOf("primhillcomputers.com");
	// This special case because hosting on OVH is specific.
	if( ixPrim >= 0 )
		// http://www.primhillcomputers.com/cgi-bin/survol/survolcgi.py?script=/sources_types/Linux/etc_passwd.py&mode=json
		// url_survol_prefix = "../cgi-bin/survol/";
		url_survol_prefix = "../cgi-bin/survol/survolcgi.py?script=/";
	else
		// url_survol_prefix = "../"; // CE QU ON AVAIT AVANT
		url_survol_prefix = "../";

	var fullUrl =  url_survol_prefix + urlQuery;

	console.log("AddUrlPrefix fullUrl="+fullUrl);

	fullUrl = AddUrlCgiArg(fullUrl, cgiArgs );

	return fullUrl;
}

// This merges the URLs given as CGI parameters, b64-encoded.
// It then displays in SVG or any mode, just like the other Python scripts.
// var pyMergeScript = AddUrlPrefix( "merge_scripts.py", "" );
var pyMergeScript = "merge_scripts.py";

// This is the name of the main window which display index.htm.
// It is needed by Summary.htm which posts messages to it.
gblWindowName = "SurvolMainWindowName";

////////////////////////////////////////////////////////////////////////////////

/*
This takes as input an array which defines several urls simultaneously
present in a D£ window. This array might come from the main window
or the summary (tool) window.
*/
function ConcatenateMergeUrl(lstLoadedUrls,cgiArgs)
{
	var urlFull;

	/* If there is one element, we might as well simply return it.
	It is a frequent case. */
	console.log("ConcatenateMergeUrl lstLoadedUrls.length="+ lstLoadedUrls.length);
	if( lstLoadedUrls.length == 1 )
	{
		urlFull = lstLoadedUrls[0].m_loaded_url;
		urlFull = AddUrlCgiArg(urlFull, cgiArgs );
	}
	else
	{
		var urlMerge = pyMergeScript;
		var cgiDelim = "?url=";

		for( var ixLoaded = 0; ixLoaded < lstLoadedUrls.length; ixLoaded++ )
		{
			var objLoadedUrl = lstLoadedUrls[ixLoaded];
			console.log("m_loaded_title="+ objLoadedUrl.m_loaded_title +" m_loaded_url="+objLoadedUrl.m_loaded_url);

			var url64safe = Base64.encodeURI(objLoadedUrl.m_loaded_url);
			urlMerge += cgiDelim + url64safe;
			cgiDelim = "&url=";
		}
	    console.log("ConcatenateMergeUrl urlMerge="+urlMerge);
    	urlFull = AddUrlPrefix(urlMerge,cgiArgs);
    }

    console.log("ConcatenateMergeUrl urlFull="+urlFull);
    return urlFull;
}

////////////////////////////////////////////////////////////////////////////////

// Current dir = http://127.0.0.1/Survol/embed_entity.htm
function LocalHost()
{
	/*
	TODO: This returns an empty string when running cgiserver.py
	*/
	pathArray = location.href;
	idxLastSlash = pathArray.lastIndexOf("/");
	return pathArray.substring(0,idxLastSlash);
}

function RdfSources()
{
	return LocalHost() + "/survol/internals/directory.py";
}

function SlpMenu()
{
	return LocalHost() + "/survol/internals/gui_slpmenu.py";
}

function DynCgi()
{
	return LocalHost() + "/survol/internals/gui_dyncgi.py";
}

// This calls GraphViz (dot) to generate a RDF file.
function RvgsToSvg()
{
	// return qualifyURL("/survol/internals/gui_create_svg_from_several_rdfs.py");
	return LocalHost() + "/survol/gui_create_svg_from_several_rdfs.py";
}

// Contains the div ids waiting to be set by the request.
var UrlInfoQueue = {};

var UrlInfoCache = {};

// BEWARE: This is full of race conditions.
function SetIdWithUrlInfo(the_url_info,title_id)
{
	// return;
	if (the_url_info in UrlInfoCache) {
        	info_txt = UrlInfoCache[the_url_info];
        	if (info_txt == false) {
			// alert("No Info for:"+the_url_info+" title="+title_id);
			return "u=" + the_url_info + " t=" + title_id + " No info (Cached)";
		}
		// Used immediately, otherwise will be set asynchronously by the Ajax request.
		return info_txt;
	}

	// Ajax request is in flight, waiting to be completed.
	if (the_url_info in UrlInfoQueue) {
		UrlInfoQueue[ the_url_info ].push( title_id );
		return "u=" + the_url_info + " t=" + title_id + " Pushed in the queue";
	}

	UrlInfoQueue[ the_url_info ] = [ title_id ];

	// Information about the URL is sent in JSON format.
	$.ajax({
	    type: "GET",
	    url: the_url_info,
	    dataType: "text", // "xml" for Chrome. To work on IE, "text" but NOT "xml" ? Not OK on IE apparently.
	    cache: true, // Maybe true ?
	    beforeSend: function (xhr) {
	        xhr.setRequestHeader("Accept", "application/json");
	    },
	    success: function (data, status, xhr) {
	        jsonInfo = jQuery.parseJSON(data);
	        jsonTxt = jsonInfo['info'];

	        UrlInfoCache[the_url_info] = jsonTxt;

	        var ourInfoQueue = UrlInfoQueue[the_url_info];

	        var szTitles = ourInfoQueue.length;
	        for (var ix = 0; ix < szTitles; ix++) {
	            titl = '#' + ourInfoQueue[ix];
	            $(titl).empty();
	            $(titl).append(jsonTxt);
	        }
	        // alert("Setting "+the_url_info+" to "+jsonTxt+" nb="+ szTitles );
	        // Will never be needed anymore because in the cache.
	        UrlInfoQueue[the_url_info] = undefined;
	    },
	    error: function (xhr, status) {
	        // alert("SetIdWithUrlInfo: Error loading:" + the_url_info + ":" + status);
	        $('#' + title_id).append("No info="+status);
	        UrlInfoCache[the_url_info] = false;
	    }
	});

	return "u=" + the_url_info + " t=" + title_id + " Requested info";
}


// This allows to print a RDF node in a HTML table.
// It shortens the link to make a nice print string.

// If it is one of our urls, we might get "info" informations.
var regex_htbin = new RegExp( ".*/survol/(.*)" );

var regex_entity = new RegExp( ".*/survol/entity.py\\?.*xid=(.*):(.*)&?" );

var rdf_node_id = 1;


/* Given a subject or object url, returns the HTML string to display.
 * */
function RdfNodeToHRef(node)
{
	// Concatenate an empty string otherwise bug ?
	var node_value = node.value + "";

	if( node.type == 'literal' )
	{
		this.entity_type = "";
		this.entity_id = "";
		this.label = node_value;
	}
	else
	{
		// Horrible hack because not sure of why this happens.
		//   file:/~rchateau/RevPython/survol/entity.py?mode=rdf&_=1416074608413
		if ( node_value.substring( 0, 6 ) == "file:/" )
		{
			node_value = "http://localhost/" + node_value.substring( 6 );
			// alert("OK:"+subj);
		}

		var res_entity = regex_entity.exec( node_value );

		// TODO: Other strings to shorten:
		// "?xid=file:%2Fhome%2Frchateau%2FDeveloppement%2FReverseEngineeringApps ..."
		// "http://192.168.1.68:80/~rchateau/RevPython/survol/sources/top/tcpdump.py?xid=:"

		// If this is an URL to an entity, try to display the id.
		if ( res_entity )
		{
			this.entity_type = res_entity[1];
			this.entity_id = res_entity[2];
			txt = res_entity[1] + " " + decodeURIComponent(res_entity[2]);
		}
		else
		{
			this.entity_type = "";
			this.entity_id = "";
			var uniq_id = "idnodetohref_" + rdf_node_id++;

			var res_htbin = regex_htbin.exec( node_value );
			if ( res_htbin )
			{
				// Then if this is a script, display the information.
				// THIS IS TEMPORARY BECAUSE BUG IN OLD FIREFOX VERSION.
				var url_info = CheckMode( node_value,"info");
				// var url_info = node_value + "&mode=info";
				var infoTxt = SetIdWithUrlInfo(url_info,uniq_id);
				txt = '<div id="' + uniq_id + '">' + infoTxt + '</div>';
			}
			else
			{
				/*
				 * TODO: Detecter si c'est une image, une video,
				 * ou tout ce qu'on peut exploiter en HTML.
				 * Do that with Ajax !
				 * */
				if(node_value.match(/\.(jpeg|jpg|gif|png)$/) != null)
				{
					txt = '<img src="' + node_value + '">';
				}
				else
				{
					txt = node_value;
				}
			}
		}
		this.url = node_value;

		// THIS IS TEMPORARY BECAUSE BUG IN OLD FIREFOX VERSION.
		// TODO: Something different than "svg".
		// PROBABLY IT SHOULD POINT TO A JAVASCRIPT CALLBACK ?
		var url_nordf = CheckMode( node_value,"svg");
		// var url_nordf = node_value + "&mode=svg";
		this.label = '<a href="' + url_nordf + '">' + txt + '</a>' ;
	}
}

////////////////////////////////////////////////////////////////////////////////

pred_prefix = "http://primhillcomputers.com/ontologies/"

// It prints a predicate into a table but shortens its name for clarity.
// var primhill = new RegExp("http://primhillcomputers.com/ontologies/(.*)");
var primhill = new RegExp( "^" + pred_prefix + "(.*)" );

function PredShorten(pred)
{
	var res = primhill.exec(pred);

	if (res) {
		return res[1];
	}
	else {
		return pred;
	}
}

// Reciprocal operation.
function PredLengthen(pred) {
	return pred_prefix + pred ;
}

////////////////////////////////////////////////////////////////////////////////

// Ensure that the CGI parameter "mode" in the url is "rdf",
// because we need RDF content.
function CheckMode(the_url_nomode, the_mode)
{
	var cgi_args_delim = "?";
	var cgi_args_str_split = the_url_nomode.split('?');
	var new_cgi_args = cgi_args_str_split[0];
	if( cgi_args_str_split.length == 2 )
	{
		var cgi_args_split = cgi_args_str_split[1].split('&');
		for( var i = 0 ; i < cgi_args_split.length; ++ i )
		{
			var keyval = cgi_args_split[i];
			if ( keyval.substring(0,5) != 'mode=' )
			{
				new_cgi_args += cgi_args_delim + keyval;
				cgi_args_delim = "&";
			}
		}
	}
	return new_cgi_args + cgi_args_delim + "mode=" + the_mode;
}

function DoLoadHtmlError( the_url, divErrMsg )
{
	$.ajax({
		type: "GET",
		url: the_url,
		dataType: "html",
		cache: false,
		beforeSend: function (xhr) {
			xhr.setRequestHeader("Accept", "text/html");
		},
		success: function (data, status, xhr) {
			// alert("Data="+data);
			/*
			 * TODO: DETECT IF THIS IS AN INDIRECTION !!!!!
			 * If the RDF script is an indirection, we must process it here
			 * because it will appear in the HTML page.
			 *
			 * If we do not do that, then the indirection appears as an HTML error message.
			*/
			$("#" + divErrMsg).html(data);
		},
		error: function (xhr, textStatus) {
			alert("error="+textStatus);
		},
	});
}

// Loads the URL of a RDF document, makes a RDF databank,
// and passes it to a callback.
function DoLoadRdfUrl( the_url_nomode, processingFunc, showErr, divErrMsg )
{
	var the_url = CheckMode(the_url_nomode,"rdf");

	/*
	 *  http://stackoverflow.com/questions/5355667/strange-underscore-param-in-remote-links
	 *
	 *  I get links like: http://localhost:3000/products?_=1300468875819&page=1
	 *  To disable the timestamp:
	 * cache: true,
	 * 
	 * use $.ajaxSetup({ cache: true }) when appropriate
	 * use a prefilter for script requests and e.g. check for urls 
	 * where you don't want the random parameter to be added
	 * and set cache: true in the prefilter for those
	 * $.ajaxPrefilter('script', function(options) { options.cache = true; });
	 * in e.g. the success call back handle the script tags yourself
	 * by doing something along these lines var elems = $(htmlwithscripttags);
	 * elems.filter("script") //now do whatever
	 * with the scripts elems.filter(":not(script)").appendTo("body"); //e.g.
	 */


	// Does not work.
	// $("body").css("cursor", "wait");

	$.ajaxSetup({cache:true});

	// TODO: Can Ajax process redirection ???

	// http://admiral-announce.blogspot.co.uk/2011/02/reading-rdfxml-in-internet-explorer.html
	$.ajax({
		type: "GET",
		url: the_url,
		dataType: "xml", // "xml" for Chrome. To work on IE, "text" but NOT "xml" ? Not OK on IE apparently.
		cache: false,
		beforeSend: function (xhr) {
			xhr.setRequestHeader("Accept", "application/rdf+xml");
		},
		success: function (data, status, xhr) {
			var tmpDataBank = jQuery.rdf.databank();
			tmpDataBank.load(data);

			processingFunc(the_url, tmpDataBank);

			// TODO: If an error happens, cannot see it on some browsers.
		},
		error: function (xhr, textStatus) {
			if ( showErr ) {
				alert("error="+textStatus);
			}

			// Maybe there is an error message in html.
			if( showErr ) {
				// Shame that we have to reload the URL differently.
				// On the other hand error messages come very quickly so this is not a disaster.
				if( textStatus == "parsererror" ) {
					DoLoadHtmlError( the_url, divErrMsg );
				}
			}
		},
	});

	// Does not work.
	// $("body").css("cursor", "default");
}

////////////////////////////////////////////////////////////////////////////////

/*
 *
 * A propos du filtrage par les types. Ca oblige a scanner dexu fois,
 * et a rescanner toute la databank en filtrant aussi sur les predicats.
 * Par ailleurs, on voudrait utiliser les ids des objects SVG
 * afin de ne detruire que ceux-la sans tout reafficher.
 * Donc quand on va afficher la premiere fois, on va garder un identifiant
 * de l'objet graphique, style svgId, et on aura une table triplet->svgId.
 *
 * Ainsi, selon le type de filtre, ca va fonctionner differement:
 * - Si filtre "custom", on l'applique uniquement sur notre container
 *   d'objets svgId, et on vire directement.
 * - Si filtre RDF, ca donnera un binding, donc subj+pred+obj,
 *   et donc les objets graphiques correspondants.
 * La premiere etape est donc de construire un container d'objets graphiques
 * etiquetes par les uri, puis les aretes etiquetees par les paires d'uris.
 * Dans le cas de l'affichage sous forme de table, seules les aretes
 * seront effectivement affichables, et pointeront vers une ligne dans une table.
 *
 * Pour preparer ca, on peut mieux parser les URLS.
 * Comme ca, ce sera fait.
 */

////////////////////////////////////////////////////////////////////////////////

// Takes the predicates of a databank and builds checkbox to select them.
function RefreshPredicates(checkboxName,displayFuncNam,predSet)
{
	onClickStr = "UpdateDatabankWithPredicates('" + checkboxName + "'," + displayFuncNam + ");";
	// alert("onClickStr="+onClickStr);

	$('#'+checkboxName).empty();
	for( var item in predSet )
	{
	        var predShort = PredShorten( item );
		$('#'+checkboxName).append(
			'<tr>'
			+ '<td><input type="checkbox" name="'
			+ item + '" '
			+ ' onClick="' + onClickStr + '" '
			+ ' checked>'
			+ predShort + '</input></td>'
			+ '<td>' + predSet[item] + '</td>'
			+ '</tr>');
	}
}

// Called when checking a predicate: Updates the display.
// checkboxName = 'CheckBoxesPredicates', typically.
function UpdateDatabankWithPredicates(checkboxName, displayFunc)
{
	var predSets = {};
	// alert("Check="+checkboxName);
	// Checkboxes with predicates such as "owns", "runs" etc...
	var predInputs = document.getElementById(checkboxName).getElementsByTagName('input');

	// First pass to see which predicates are checked.
	for( var idx = 0; idx < predInputs.length; ++idx )
	{
		inp = predInputs[idx];
		if ( inp.checked )
		{
			// Any value is OK.
			predSets[ inp.name ] = true;
		}	
	}

	// Now keep only the triples whose predicate is checked.
	// TODO: Optimization, if all predicates are checked, no filter.
	var dataBankQuery
	= $.rdf({ databank: rdfDataBank })
	.where('?subj ?pred ?obj')
	.filter( function()
	{
		return this.pred.value in predSets ;
	} );

	var dbBindings = dataBankQuery.select();

	// alert("Subselection l="+dbBindings.length);

	// ICI: On ne passe pas de callbacks au redrawer.
	displayFunc(dbBindings);
	// alert("After Subselection");
}

////////////////////////////////////////////////////////////////////////////////

// This is what we should use to merge the databanks but it does not work.
// rdfDataBank.add( newRdfDb );
function MergeDatabanks( rdfDataBank, newRdfDb )
{
	// Not sure this is useful.
	$.ajaxSetup({cache:true});
	var newLength = newRdfDb.size();

	// TODO: If the target darabank is empty, just assign.
	var newTriples = newRdfDb.triples();
	for (var i = 0; i < newLength; i++) {
		rdfDataBank.add(newTriples[i]);
	}
}

// To be displayed in title.
function NiceHostname()
{
	if (location.hostname == "127.0.0.1")
		return "localhost";
	return location.hostname;
}
////////////////////////////////////////////////////////////////////////////////

