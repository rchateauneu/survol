function onDrop(evt) {
    evt.stopPropagation();
    evt.preventDefault();
    var droppedUrl = evt.dataTransfer.getData("URL");

    console.log("onDrop droppedUrl=" + droppedUrl);

    var adaptedUrl = null;

    /* The URL can be a Python script:
    http://127.0.0.1:8000/survol/sources_types/odbc/table/odbc_table_columns.py?xid=odbc/table.Dsn%3DDSN~MyNativeSqlServerDataSrc%2CTable%3DCOLUMN_DOMAIN_USAGE
    This detection is not very reliable, but the only bad consequence is loading badly-formatted Json data.
    */
    ixSourcesTypes = droppedUrl.indexOf("/sources_types/");
    if(ixSourcesTypes >= 0) {
        adaptedUrl = AppendCgiToUrl(droppedUrl, "mode=json");
    }

    if(adaptedUrl) {
        /* If the URL has the right style, it is added. This always merges. */
        /*
        Nodes from various hostnames must have something specifically visible,
        when it is different from the current host.
        The host is extracted from the url.
        Maybe a specific css could be loaded from this remote machine.
        */
        loadUrlUpdateDisplay(adaptedUrl,true);
    }
    else
    {
        alert("Cannot drop url:"+droppedUrl);
    }
};

function onDragOver(evt){
    console.log("onDrag evt=" + JSON.stringify(evt))
    evt.preventDefault();
}

function D3DisplayCreation()
{
    'use strict';

    // For HTML documents the returned object is the <html> element.
    var eltDocElt = document.documentElement;
    var gebBody = document.getElementsByTagName('body')[0];

    gebBody.addEventListener('drop', onDrop);
    gebBody.addEventListener('dragover', onDragOver, false);

    // No scrolling. Could not find a way to set the exact size of the document.
    $("body").css("overflow", "hidden");

    divSvg = d3.select("#MainDiv")
        .classed("svg-container", true) //container class to make it responsive
        .append("svg:svg")
        ;

    var defs = divSvg.append('svg:defs');

    // https://css-tricks.com/svg-path-syntax-illustrated-guide/
    var dataMarker = [
        { id: 0, name: 'marker_circle', path: 'M 0, 0  m -5, 0  a 5,5 0 1,0 10,0  a 5,5 0 1,0 -10,0', viewbox: '-6 -6 12 12' },
        { id: 1, name: 'marker_square', path: 'M 0,0 m -5,-5 L 5,-5 L 5,5 L -5,5 Z', viewbox: '-5 -5 10 10' },
        { id: 2, name: 'marker_arrow_org', path: 'M 0,0 m -5,-5 L 5,0 L -5,5 Z', viewbox: '-5 -5 10 10' },
        { id: 3, name: 'marker_arrow', path: 'M 0,0 m -35,-2 L -25,0 L -35,2 Z', viewbox: '-35 -5 15 10' },
        { id: 4, name: 'marker_stub', path: 'M 0,0 m -1,-5 L 1,-5 L 1,5 L -1,5 Z', viewbox: '-1 -5 2 10' }
    ];

    var colorMarker = d3.scaleOrdinal(d3.schemeCategory10);

    var marker = defs.selectAll('marker')
        .data(dataMarker)
        .enter()
        .append('svg:marker')
        .attr('id', function(d){ return d.name})
        .attr('markerHeight', 20)
        .attr('markerWidth', 20)
        .attr('markerUnits', 'strokeWidth')
        .attr('orient', 'auto')
        .attr('refX', 0)
        .attr('refY', 0)
        .attr('viewBox', function(d){ return d.viewbox })
        .append('svg:path')
        .attr('d', function(d){ return d.path })
        // https://stackoverflow.com/questions/21060391/make-marker-end-same-color-as-path : Make marker-end same color as path?
        .attr('fill', "black")
        ;

    function SetSvgRect()
    {
        var divHeader = document.getElementById("HeaderDiv");
        var heightHeader = divHeader.offsetHeight;

        wScreen = Math.max(window.innerWidth, eltDocElt.clientWidth, gebBody.clientWidth);
        hScreen = Math.max(window.innerHeight, eltDocElt.clientHeight, gebBody.clientHeight);
        wScreen -= 20;
        hScreen -= (heightHeader + 30); // TODO: Must take into account the text size.

        // If we do not use "viewBox" and "preserveAspectRatio".
        divSvg
            .attr("width", wScreen)
            .attr("height", hScreen)
            ;
    }

    // If the drag behavior prevents the default click,
    // also stop propagation so we don’t click-to-zoom.
    function stopped() {
      if (d3.event.defaultPrevented) d3.event.stopPropagation();
    }

    SetSvgRect();

    divSvg
        .attr("style","border-style:solid;border-width:1px;")

        //.attr("preserveAspectRatio", "xMinYMin meet")
        //.attr("viewBox", "0 0 " + wScreen + " " + hScreen)
        .classed("svg-content-responsive", true)
        ;

    divItselfG = divSvg.append("sgv:g");

    function updateWindow(){
        SetSvgRect();
    }
    d3.select(window).on('resize.updatesvg', updateWindow);

    function zoomFunction() {
        divItselfG.attr("transform", d3.event.transform);
    }

    var zoom = d3.zoom()
        .scaleExtent([0.125, 8])
        .on("zoom", zoomFunction);

    divSvg.call(zoom);

    if(false)
    {
        divSvg.on("click", stopped, true);
    }

    myForce = d3.forceSimulation();
} // D3DisplayCreation



function displayD3Layout(divItselfG,newData,w,h)
{
    'use strict';
    console.log("displayD3Layout newData.nodes="+newData.nodes.length+" newData.links="+newData.links.length);

    function tick_function()
    {
        /* Apply the constraints: On verra plus tard.
        using layout.force to plot tree graphs (where nodes may have multiple parents) - Part 1: pure tree
        http://bl.ocks.org/GerHobbelt/3669455
        */

        survolLinks
            .attr("x1", function (d) { return d.source.x; })
            .attr("y1", function (d) { return d.source.y; })
            .attr("x2", function (d) { return d.target.x; })
            .attr("y2", function (d) { return d.target.y; });

        // http://mbostock.github.io/d3/talk/20110921/bounding.html
        selectedNodes.attr("transform", function (d) {
            /*
            // TODO: This works but is not very nice..
            var rr = 10;
            d.x = Math.max(rr, Math.min(w - rr, d.x));
            d.y = Math.max(rr, Math.min(h - rr, d.y));
            */

            return "translate(" + d.x + "," + d.y + ")";
        });
    }

   // It is possible to link nodes by names in D3 v4: https://bl.ocks.org/mbostock/533daf20348023dfdd76
    myForce
        .nodes(newData.nodes);

    var forceLink = d3
        .forceLink().id(
            function (d)
            {
                return d.id;
            }
        )
        .distance(
            function (d)
            {
                // return GetNodeDefaults(d.label).linkDistance;
                // console.log("stroke link attr d.link_class="+d.link_class);
                if( d.link_class == undefined ) {
                    return 200;
                } else {
                    // This represents the only link_class at the moment,
                    // when two objects have the same alias.
                    return 10;
                    }
            }
        )
        .strength(0.1);

    myForce
        .force("link", forceLink)
        .force("charge", d3.forceManyBody().strength(-200))
        .force("center", d3.forceCenter(wScreen / 2, hScreen / 2));

    myForce.force("link")
        .links(newData.links);

    myForce
        .force("x",d3.forceX(wScreen))
        .force("y",d3.forceY(hScreen))
        .on("tick", tick_function);

    var survolLinks = divItselfG.selectAll(".survol_line")
        .data(newData.links)
        .enter().append("svg:line")
        .attr("class", function (d) { return "survol_line"; })
        .attr("x1", function (d) { return d.source.x; })
        .attr("y1", function (d) { return d.source.y; })
        .attr("x2", function (d) { return d.target.x; })
        .attr("y2", function (d) { return d.target.y; })

        // TODO: The marker should take the same color as the line.
        .style("marker-end", function (d) {
            if( d.link_class == undefined )
                // TODO: Bidirectional arrays should be displayed so.
                return "url(#marker_arrow)";
            else {
                // Alias links do not get an arrow.
                return undefined;
                }
        })
        // .append("svg:title").text(function(d) { return d.link_prop; })

        // Could not find a way to use CSS.
        // TODO: Change styles with parameters.
        .style("stroke", function (d) {
            // console.log("stroke link attr d.link_class="+d.link_class);
            if( d.link_class == undefined )
                return "black";
            else {
                return "red";
                }
        })
        .style("stroke-dasharray", function (d) {
            // console.log("stroke-dasharray link attr d.link_class="+d.link_class);
            if( d.link_class == undefined )
                return undefined;
            else {
                return ("10,3");
                }
        })
        .style("stroke-width", function (d) {
            // console.log("stroke-dasharray link attr d.link_class="+d.link_class);
            if( d.link_class == undefined )
                return 1;
            else {
                return 3;
                }
        })
        ;

    // D3V4 START
    function dragstarted(d) {
        if (!d3.event.active) myForce.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;

        isDragging = true; // This avoids the tooltip when dragging.
        // console.log("Tooltip disabled");
    }

    function dragged(d) {
        d.fx = d3.event.x;
        d.fy = d3.event.y;
    }

    function dragended(d) {
        if (!d3.event.active) myForce.alphaTarget(0);
        d.fx = null;
        d.fy = null;

        d3.event.sourceEvent.stopPropagation(); // silence other listeners
        isDragging = false; // Tooltip when hovering is now allowed.
        // console.log("Tooltip enabled");
    }

    var d3BehDrag = d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended)

    // Creates one SVG object (Which class ?) for each survol node.
    var selectedNodes = divItselfG.selectAll("g.node")
        .data(newData.nodes)
        .enter().append("svg:g")
        .attr("class", function (d)
            {
                // return "survol_node node " + d.entity_class;
                return "survol_node " + d.entity_class;
            }
        ) // Several classes are possible.
        .call(d3BehDrag);
        ;

	/* https://stackoverflow.com/questions/30723592/prevent-click-action-when-dragging-a-d3-node
	When combining drag with other event listeners, stop propagation on the source event to prevent multiple actions.
	Otherwise, dragging also triggers the click behavior when the mouse is released. */

    // Define the div for the tooltip.
    // If set globally, it is null here.
    divTooltip = d3.select("body").append("div")
        .attr("class", "tooltip")
        .style("opacity", 0.5)
        ;

    // Used for the tooltip containg literal nodes pointing to a given node, i.e. information.
    // TODO: This should be recursive.
    function dictToTable(theList, theDict)
    {
        var result = "<table>"
        for (var ix in theList) {
            result += "<tr><td valign='top' align='left' colspan='2'><b>" + theList[ix] + "</td></tr>";
        }
        for (var key in theDict) {
            if (theDict.hasOwnProperty(key)) {
                result += "<tr><td valign='top' align='left'><b>"
                       + key + "</b></td><td valign='top' align='left'>" + theDict[key] + "</td></tr>";
            }
        }
        result += "</table>";
        return result;
    } // dictToTable

    // https://bl.ocks.org/mbostock/7555321 Wrapping Long Labels
    function addTextLines(selection) {
        selection.each(function(d) {
            // Helper function to add a string at the bottom of the text SVG object.
            function TextAppender() {
                return theText.append("tspan").attr("x", 0).attr("dy", 1 + "em");
            }

            var theText = d3.select(this);
            // This is the first line of the box.
            TextAppender().attr("text-anchor", "middle").text(d.name);

            // Now it displays one line for each information about the node.
            var cntLine = 0;

            // These are the properties without key.
            for (var ix in d.survol_info_list) {
                TextAppender().text(d.survol_info_list[ix]);
            }

            // This display the key-value pairs properties of an object.
            for (var key in d.survol_info_dict) {
                if (d.survol_info_dict.hasOwnProperty(key)) {
                    var valInfo = d.survol_info_dict[key];

                    // FIXME: This is a temporary solution until we have automatic wrapping.
                    if( valInfo.length > 30 )
                    {
                        var arrVals = NiceTextSplit(valInfo,30)

                        // Print first line with the key.
                        var txtKeyVal = key + "=" + arrVals[0];
                        TextAppender().text(txtKeyVal);

                        // Rest of the value on different lines.
                        for( var ixLin = 1; ixLin < arrVals.length; ixLin++ )
                            TextAppender().text(arrVals[ixLin]);

                    }
                    else
                    {
                        var txtKeyVal = key + "=" + valInfo;
                        TextAppender().text(txtKeyVal);
                    }
                }
            }
        })
    } // addTextLines

    function getTextBox(selection) {
        selection.each(function(d) { d.bbox = this.getBBox(); })
    }

    // This is the text associated to each survol node.
    // TODO: Properly align text: Title in the center, key-value paiss left-align.
    // TODO: Set text box maximum size, because of automatic wrapping.
    selectedNodes.append("svg:text")
        .attr("class", "nodetext")
        .attr("dx", 0)
        .attr("dy", ".35em")
        .attr("text-anchor", "middle")
        .call(addTextLines)
        .call(getTextBox)
    ;

    // Adds text inside each "g" object of class "survol_node": http://stackoverflow.com/questions/6725288/svg-text-inside-rect
    // Inserts the rect element before the text, which is therefore not hidden.
    // The node must be in "survol_node" and with the class
    d3.selectAll(".survol_node").insert("rect","text")
        .attr("x", function(d){return d.bbox.x})
        .attr("y", function(d){return d.bbox.y})

        .attr("rx", 5) // NOTE: Could not find a way to override this with CSS
        .attr("ry", 5)
        .attr("opacity", 1)

        .attr("width", function(d){return d.bbox.width})
        .attr("height", function(d){return d.bbox.height})
        .attr("stroke-width", function (d) { return d.survol_width; } )
        .attr("stroke", function (d) { return d.survol_stroke; } )
        // Classes are not defined so fill colors are OK. We will fetch CSS in classes directories.
        .attr("fill", function (d) {
            if(d.survol_fill)
                // Returned by the Python script.
                return d.survol_fill;
            else
                // Default value which applies for ActiveX if there is no CSS.
                return "#E0E0E0";
        })
        // This allows to apply a CSS with the same name.
        .attr("class", function (d) { return d.entity_class; })
        .on("mouseover", function(d)
            {
                // No tooltip creation when dragging because it is very CPU-consuming.
                if(isDragging) {
                    console.log("No tooltip when dragging");
                    return;
                }
                d.is_mouseover = true;

                // Loading a URL is very heavy. Maybe we should wait some tenths of seconds to check
                // if we are still on this node, before loading the tooltip.
                function IfMouseOver(d,currentEventD3pageX,currentEventD3pageY)
                {
                    if( false == d.is_mouseover ) {
                        // console.log("MouseOver too late");
                        return;
                        }
                    if( isDragging ) {
                        // console.log("IfMouseOver not when dragging");
                        return;
                        }

                    // This object probably comes from WMI only.
                    // TODO: We could still have a URL and rather check if a server is here ??
                    if( ! d.survol_url ) {
                        console.log("No script data without URL");
                        return;
                        }
						
                    // d.survol_info_dict is a dictionary, and survol_info_list is a list.
                    // These two members are filled when parsing the input JSON document.

                    // console.log("IfMouseOver d.survol_url="+d.survol_url);
                    var urlReplaced = d.survol_url.replace("entity.py","entity_info_only.py");
                    var urlTooltip = AppendCgiToUrl(urlReplaced,"mode=json");

                    console.log("Loading urlTooltip="+urlTooltip);

                    // TODO: Replace with XML, so the conversion RDF => D3 is done in the browser.
                    d3.json(urlTooltip,
                        function(error,objTooltip)
                        {
                            function DisplayTooltipDiv(theTooltipText)
                            {
                                // console.log("DisplayTooltipDiv theTooltipText="+theTooltipText);

                                // http://stackoverflow.com/questions/36326683/d3-js-how-can-i-set-the-cursor-to-hand-when-mouseover-these-elements-on-svg-co
                                // This could as well be done in CSS, but we might wish not change the pointer if no link is available, i.e. faulty node.
                                d3.select(this).style("cursor", "pointer");

                                divTooltip.transition()
                                    .duration(200)
                                    .style("opacity", .9);

                                divTooltip.html( theTooltipText )
                                    .style("left", (currentEventD3pageX) + "px")
                                    .style("top", (currentEventD3pageY - 28) + "px");
                            }

                            if(error)
                            {
                                var errMsg = "Tooltip error:" + error + " urlTooltip="+urlTooltip;
                                DisplayTooltipDiv(errMsg);
                                return;
                            }
                            // console.log("Callback urlTooltip="+urlTooltip+ " objTooltip="+JSON.stringify(objTooltip));
                            if( objTooltip.survol_error != undefined )
                            {
                                var errMsg = "Tooltip objTooltip.survol_error="+objTooltip.survol_error;
                                DisplayTooltipDiv(errMsg);
                                return;
                            }
                            if( false == d.is_mouseover ) {
                                // console.log("After tooltip loaded: too late");
                                return;
                                }

                            if( isDragging ) {
                                // console.log("No tooltip when dragging");
                                return;
                                }

                            if( objTooltip == null ) return ;
                            if( typeof(objTooltip.nodes) == 'undefined' ) return ;
                            if( typeof(objTooltip.nodes[0]) == 'undefined' ) return ;

                            // THIS MUST BE REPLACED BECAUSE UGLY AND NOT FLEXIBLE.
                            var objInfo = objTooltip.nodes[0].survol_info_dict
                            if ( typeof(objInfo) != 'undefined')
                            {
                                var txtTooltip = dictToTable([],objInfo);
                                DisplayTooltipDiv(txtTooltip);
                            }
                        }
                    );
                } // IfMouseOver

                var currentEventD3 = d3.event;

                // Tooltip starts only after 500 milliseconds.
                setTimeout( function() { IfMouseOver(d,currentEventD3.pageX,currentEventD3.pageY); } , 500 );
            }
        )
        .on("mouseout", function(d)
            {
                d.is_mouseover = false;

                // This could as well be done in CSS.
                d3.select(this).style("cursor", "default");

                divTooltip.transition()
                    .duration(500)
                    .style("opacity", 0);
            }
        )
        /*
        .on("click", function(d)
            {
                // TODO: Disabled for the moment because we do not know how to
                // make it work with drag. Consider double-click ??
                // This option is not mandatory because it is still possible to right-click.
                console.log("CLICK is disabled");
                return;

                // Removes immediately tooltip if it is here.
                // divTooltip.style("opacity", 0);

                // This expects a graph, not a contextual menu.
                var aUrl = AppendCgiToUrl( d.survol_url, "mode=json");
                console.log("aUrl="+aUrl);
                loadUrlUpdateDisplay(aUrl, false);
            })
        */
        ;

    // var radius = d3.scale.log().domain([0, 312000]).range(["10", "50"]);

    // Is that to avoid collisions ? Is the drag needed here ?
    d3.selectAll(".circle").append("circle")
        .attr("class", function (d) { return "node"; })
        ;

    // This returns the contextual menu for nodes.
    function makeContextMenuItems(objectSvg)
    {
        // SHOULD CALL entity_info_only.py BUT THE PROBLEM IS THAT IT IS NOT THE ORIGINAL NODE
        // SO THERE IS A CONFUSION WITH entity.py THAT EVERYTHING RELIES ON.
        // ALSO, WHEN mode=json WE SHOULD NOT DISPLAY THE WBEM AND WMI LINKS AND THE SCRIPTS.
        // MAYBE A ANOTHER MODE NEEDED FOR JUST TEXT INFORMATION FOR THE TOOLTIP.
        // BUT THIS IS VERY HEAVY TO CALL THIS EACH TIME WE HOVER OVER A NODE.
        var objUrl = objectSvg.survol_url;
        console.log("makeContextMenuItems objUrl="+objUrl);

        var objKey = objectSvg.name;

        var objDeferScripts = objectSvg.defer_scripts;
        // if (typeof objDeferScripts != 'object') {
        // This tests of it is a Json object by comparing the constructors.
        // if (objDeferScripts && objDeferScripts.constructor === Promise().constructor)

        if (!isPromise(objDeferScripts)) {
            alert("Should be a promise object:" + typeof(objDeferScripts));
        }
        console.log("makeContextMenuItems objKey=" + objKey);

        // TODO: Add URLs for wmi and WBEM.

        var TheItems = {};

        // This is the title, and it is clickable.
        TheItems[objUrl] =
        {
            name : objKey
        };

        /* The Survol agent has a WMI url only if this is a CIM class and if this is Windows machine.
        More: If the object specifies a different host than the Survol agent, and of the survol
        agent has a WMI api without being a Windows machine, it is still possible to have a valid URL.
        */
        function createUrlWMI(aSurvolUrl)
        {
            console.log("createUrlWMI aSurvolUrl=" + aSurvolUrl);
            // aSurvolUrl = "http://127.0.0.1:8000/survol/entity.py?xid=rabbitmq/connection.Url=LOCALHOST:12345,Connection=127.0.0.1:51759 -&gt; 127.0.0.1:5672&mode=json"
            // var strDelim = "entity_info_only.py?xid="
            var strDelim = "entity.py?xid="
            var posQuestion = aSurvolUrl.indexOf(strDelim);
            console.log("createUrlWMI aSurvolUrl=" + aSurvolUrl);
            if (posQuestion < 0 )
            {
                return null;
            }

            // var urlWMI = "http://mymachine:8000/survol/entity_wmi.py?xid=\\mymachine\root\CIMV2%3ACIM_Process.Handle%3D8200&mode=json";
            var subsPrefix = aSurvolUrl.substring(0, posQuestion ); // "http://mymachine:8000/survol/"
            console.log("createUrlWMI subsPrefix=" + subsPrefix);
            var subsMoniker = aSurvolUrl.substring(posQuestion + strDelim.length); // "rabbitmq/connection.Url=LOCALHOST:12"
            var posDot = subsMoniker.indexOf(".");
            if (posDot < 0 )
            {
                // If no class.
                return null;
            }
            var strClass = subsMoniker.substring(0,posDot);

            // Check if this is a CIM class. Similar function in lib_wmi.py
            function isValidClassWmi(className)
            {
                console.log("isValidClassWmi className="+className);
                var posUnderscore = className.indexOf("_");
                if( posUnderscore < 0 )
                {
                    return false;
                }
                var tpPrefix = className.substring(0,posUnderscore);
                return (tpPrefix == "CIM") || (tpPrefix == "Win32") || (tpPrefix == "WMI");
            }

            if ( ! isValidClassWmi(strClass) )
            {
                return null;
            }

            // myHost = "mymachine:8000"
            var myHost = GetHostFromUrl(aSurvolUrl);
            var posColon = myHost.indexOf(":");
            if(posColon >= 0)
            {
                myHost = myHost.substring(0,posColon);
            }
            // ":" == "%3A"

            // Expected result: "http://mymachine:8000/survol/entity_wmi.py?xid=CIM_Process.Handle=1200&mode=json"
            // The WMI host and namespace are not taken into account.
            var urlWMI = subsPrefix + "entity_wmi.py?xid=" + subsMoniker;
            console.log("createUrlWMI urlWMI="+urlWMI);

            // http://mymachine:8000/survol/entity_wmi.py?xid=CIM_Process.Handle=1200&mode=json
            // http://mymachine:8000/survol/entity_wmi?xid=CIM_Process.Handle=1200&mode=json

            return urlWMI;
        }

        console.log("makeContextMenuItems objUrl="+objUrl);
        var urlWMI = createUrlWMI(objUrl);
        if(urlWMI) {
            TheItems[urlWMI] = {
                "name": "WMI server-side",
                "icon": "paste"
            };
        }

        var urlWBEM = null;
        // var urlWBEM = "http://mymachine:8000/survol/entity_wbem.py?xid=\\mymachine\root\CIMV2%3ACIM_Process.Handle%3D8200&mode=json";
        if(urlWBEM) {
            TheItems[urlWBEM] = {
                "name": "WBEM server-side",
                "icon": "paste"
            };
        }

        // If CIM_DataFile, this creates a MIME link on the fly.
        function urlCIM_DataFileToMime(url)
        {
            if(url.indexOf("survol/entity.py?xid=CIM_DataFile.") < 0)
                return null;
            return url.replace("survol/entity.py","survol/entity_mime.py");
        }

        var urlMime = urlCIM_DataFileToMime(objUrl);
        if(urlMime) {
            TheItems[urlMime] = {
                "name": "Mime Display",
                "icon": "paste"
            };
        }

        /*
        Get a list of KV pairs with the parameters.

        We must edit the parameters of the script, not of the object.
        When executing a script, it must send its parameters in JSON, in a special format,
        optional, which does not change the nodes/links data.

        Submitting means:
        - Removing the URL.
        - Create a new URL
        - Load and merge it.

        What does it mean to edit the parameters of an object ?
        We would have to reload "entity" but this mean chaning the object and
        also everything linked to it.
        But we keep open the possibility to act upon an object,
        or change future display parameters.
        To prepare this, we should find a general parameter which always applies.
        */

        // Not needed if this is an external URL.
        if( objUrl.indexOf("survol/") >= 0 ) {
            // By default, results of scripts is merged with the current graph.
            var TheItemsSuite =
            {
                "yesno": {
                    name: "Merge graphs",
                    type: 'checkbox',
                    selected: true
                }
                /* ,
                "disp_all": {
                    name: "Display all scripts",
                    type: 'checkbox', // type: 'text',
                    // value: "Test data",
                    selected: false,
                    events: {
                        keyup: function(e) {
                            // add some fancy key handling here?
                            window.console && console.log('key: '+ e.keyCode);
                        }
                    }
                }
                */
            };
            jQuery.extend(TheItems, TheItemsSuite);
        }

		// Maybe there are Python scripts for this object.
		if(objDeferScripts) {
			// https://swisnl.github.io/jQuery-contextMenu/demo/async-promise.html Submenu through promise.
			var menusSurvol = objDeferScripts.promise();
            console.log("menusSurvol.state()=", menusSurvol.state());
            console.log("menusSurvol=", menusSurvol);
            if ( menusSurvol.state() == "resolved" ) {
                menusSurvol.then( function(ms) {
                    menusSurvol = ms;
                    // contextMenu does not want a promise which is resolved.
                    // TBH, the logic is not very clean. So if it is resolved, it is replaced with the value.
                    // TODO: Consider not resolving it, and just giving the prmise "as is" to contextMenu.
                    console.log("RESOLVED menusSurvol=", menusSurvol);
                });
            }

			var TheItemsScripts = {
				"sep1": "---------",
				"SurvolMenu": {
					name: "Scripts...",
					items: menusSurvol,
				}
			};
			jQuery.extend(TheItems, TheItemsScripts);
		}

		// objectSvg contains the original object created from the WMI command.
		// But it might also simply contain the attribute taken from the URL ?
		// Or we should parse the URL and add the properties into it (and the class),
		// so we could query from WMI with just our properties ??
		// Problem with Base64 ? But why not detecting on the fly if a string is Base64-encoded ??
		// PROBLEM: We have lost the class used from the query. This is not:
		// "CreationClassName, "CSCreationClassname", "OSCreationClassName".
		// Or is it in "entity_class" ?
		// TODO: Should add it.
		if(objUrl) {
			console.log("Calling ActiveX_WMI_JContextMenu objUrl="+objUrl);

			// This creates a clickable item which calls RefillDisplay with the associators objects
			// transformed into a JSON graph.

			var TheItemsSuiteActiveX = ActiveX_WMI_JContextMenu(objUrl,objectSvg, rememberCallback );

			// console.log("Called ActiveX_WMI_JContextMenu objUrl="+objUrl);
			if( TheItemsSuiteActiveX != [] )
			{
				jQuery.extend(TheItems, TheItemsSuiteActiveX);
			}
		}

        var theItemsSuiteDels =
        {
            "delete_node": {
                "name": "Delete node",
                "icon": "delete"
            },
            "delete_connected": {
                "name": "Delete connected nodes",
                "icon": "delete"
            }
        };
        jQuery.extend(TheItems, theItemsSuiteDels);

        return TheItems;
    } // makeContextMenuItems


    /*
    On veut utiliser les menus en XML comme ceux de entity_menu_seealso.py et on va zapper entity_dirmenu_only.py
    Alors, il faut transformer le RDF en ce que veux contextMenu.
    C'est logique : Le backend ne doit rien connaitre du front-end.
    En revanche ca oblige a mettre rdflib dans le front-end.
    Mais toutefois, RDF est un standard au contraire de notre format json.
    */
    const DCT = $rdf.Namespace("http://purl.org/dc/terms/");
    const RDFS = $rdf.Namespace("http://www.w3.org/2000/01/rdf-schema#");

    function xmlToMenu_NOT_USED_YET(xmlMenuAsString) {
        let rdfMenu = $rdf.graph();
        console.log("xmlToMenu");
        console.log("typeof(xmlMenuAsString)=", typeof(xmlMenuAsString));
        console.log(xmlMenuAsString);
        // It is a pity that we serialize the string to a XML document then to a string.
        //var xmlMenuAsString = new XMLSerializer().serializeToString(xmlMenu);
        $rdf.parse(xmlMenuAsString, rdfMenu, window.location.origin, 'application/rdf+xml');
        // rdfMenu = $rdf.parseXML(xmlMenu);
        var menuSurvol = menuRdfToContextMenu(rdfMenu);
        return menuSurvol;
    } // xmlToMenu_NOT_USED_YET

    function menuRdfToContextMenu_NOT_USED_YET(store, baseUri) {
        console.log('seeAlsoToMenu: Building menu hierarchy from store with base URI:', baseUri);
        // Base URI is required by rdflib to shorten relative internal references like "/menu/..."

        function buildHierarchy(node) {
            const labelNode = store.any(node, RDFS('label'));
            // The user requested dct:seeAlso. We check both DCT and RDFS namespaces for robustness.
            const seeAlsoNode = store.any(node, RDFS('seeAlso'));
            const childrenNodes = store.each(node, DCT('hasPart'));

            // Use label from RDF, or fallback to a shortened version of the URI value
            const label = labelNode ? labelNode.value : node.value.replace(baseUri, '');
            const item = { name: label };

            if (seeAlsoNode) {
                console.log('seeAlsoToMenu : Found seeAlso for', node.value, ':', seeAlsoNode.value);
                item.url = seeAlsoNode.value;
            }

            if (childrenNodes.length > 0) {
                item.items = childrenNodes.map(child => buildHierarchy(child));
            }

            return item;
        }

        // Root detection: Find nodes that have parts but are not parts themselves.
        const subjectsWithParts = store.each(undefined, DCT('hasPart'), undefined);
        const uniqueSubjects = [...new Set(subjectsWithParts.map(s => s))];

        const roots = uniqueSubjects.filter(uri => {
            const node = uri;
            return !store.any(undefined, DCT('hasPart'), node);
        });

        // Map each root to its hierarchy.
        // If the top-level node is just a container (no label/url), we could return its children instead.
        return roots.map(rootUri => buildHierarchy(rootUri));

        var dfltItmsExample =
        {
            "xxxx": {
                name: "xxxx",
                type: 'checkbox',
                selected: false
            },
            "yyyy": {
                "name": "yyyyy",
                "items": {
                    "edit": {"name": "Edit", "icon": "edit"},
                    "cut": {"name": "Cut", "icon": "cut", disabled: true},
                    "quit": {"name": "Quit", "icon": "quit"}
                }
            }
        };
    } // menuRdfToContextMenu_NOT_USED_YET

    /* This returns the contextual menu for the background.
    It is immediately superseded, and the sample data are here just for documentation.
    It contains example data, to explain its structure. */
    function makeDefaultContextMenuItems(objectSvg)
    {
        var theDfltItems =
        {
            "xxxx": {
                name: "xxxx",
                type: 'checkbox',
                selected: false
            },
            "yyyy": {
                "name": "yyyyy",
                "items": {
                    "edit": {"name": "Edit", "icon": "edit"},
                    "cut": {"name": "Cut", "icon": "cut", disabled: true},
                    "quit": {"name": "Quit", "icon": "quit"}
                }
            }
        };
        return theDfltItems;
     } // makeDefaultContextMenuItems

    /* Called after the page is loaded. It adds a context menu to each node,
    therefore the nodes must be created. A lot of information here:
    https://github.layalk.net/jQuery-contextMenu/docs.html */
    function createContextMenus(){
        console.log("createContextMenus");

        // Goes to the right URL given the selected key of a contextual menu.
        function fromKeyToScript(key, options, objectSvg)
        {
            // We will merge the new content with the existing content or not.
            var menuOptions = {};
            $.contextMenu.getInputValues(options, menuOptions);
            // This applies to the two types of contextual menu: Per node or general.

            // This is a Python script, but not a contextual menu displayed by "entity.py".
            var theUrl = AppendCgiToUrl( key, "mode=json");
            console.log("fromKeyToScript theUrl="+theUrl);
            loadUrlUpdateDisplay(theUrl, menuOptions.yesno, objectSvg );
        }

        // For an URL which returns HTML and to be opened in its own window.
        // Similar to _script_for_json in Python.
        function plainNonEntityUrl(url)
        {
            if( url.indexOf("survol/entity_mime.py") >= 0 )
            {
                return true;
            }
            if( url.indexOf("survol/") >= 0 )
            {
                return false;
            }
            // This is a foreign URL
            return true;
        } // plainNonEntityUrl

        $.contextMenu(
        {
            selector: 'g.survol_node',

            build: function($trigger, evt) {
                // This callback is executed every time the menu is to be shown
                // Its results are destroyed every time the menu is hidden
                // evt is the original contextmenu event, containing evt.pageX and evt.pageY (amongst other data)

                // In JSON format, the node on which we have right-clicked.
                var objectSvg = $trigger["0"]["__data__"];

                var theItems = makeContextMenuItems(objectSvg);

                return {
                    // This is executed when an option is chosen in a contextual menu.
                    callback: function(key, options)
                    {
                        if(key == "delete_node")
                        {
                            // TODO: Have a specific callback.
                            DeleteSvgNode(objectSvg);
                        }
                        else if(key == "delete_connected")
                        {
                            deleteSvgConnectedNodes(objectSvg);
                        }
                        else
                        {
                            if( plainNonEntityUrl(key) )
                            {
                                window.open(key, '_blank','location=no,height=570,width=520,scrollbars=yes,status=yes');
                                return;
                            }
                            // The coordinates of new nodes merged in the current graph must be initialised
                            // with the coordinates of the current node, objectSvg. This makes the drawing more
                            // natural and the routing more efficient.
                            fromKeyToScript(key, options, objectSvg);
                        }
                    },
                    items: theItems
                };
            }
        });

        // TODO: Apparently not used.
        var dfltItms = makeDefaultContextMenuItems();

        /* There is one default menu, loaded once and for all,
        and it does not use the "promise" feature of the library.
        Therefore it is built asynchronously. */

        // Adds a context menu for the background.
        function addDefaultCtxtMenu(error, dfltItms)
        {
            console.log("addDefaultCtxtMenu entering");
            if(error) {
                alert("addDefaultCtxtMenu error="+error);
            }
            if(dfltItms == undefined) {
                alert("addDefaultCtxtMenu dfltItms undefined");
            }
            if(dfltItms.survol_error != undefined)
            {
                alert("Error:"+dfltItms.survol_error);
                return;
            }
            $.contextMenu(
            {
                selector: 'svg',
                build: function($trigger, evt) {
					// This does not need the Python HTTP server.
					console.log("ActiveX_WMI_JCtxtMenuGlobal before");

					var activeXDefaultMenus = ActiveX_WMI_JCtxtMenuGlobal(rememberCallback);

					console.log("ActiveX_WMI_JCtxtMenuGlobal after");
					if( activeXDefaultMenus )
					{
					    console.log("activeXDefaultMenus="+JSON.stringify(activeXDefaultMenus));
        				dfltItms["sep2"] = "---------";

						dfltItms["wmiglobal"] = {
							name: "WMI Globals",
							"items" : activeXDefaultMenus
						};
					}

                    // This adds an extra item to the menu returned by a Python script.
                    dfltItms["yesno"] = {
                        name: "Merge graphs",
                        type: 'checkbox',
                        selected: false
                    };

                    return {
                        callback: function(key, options)
                        {
                            console.log("callback key=" + key);
                            fromKeyToScript(key, options);
                        },
                        items: dfltItms
                    };
                }
            });
            console.log("addDefaultCtxtMenu leaving");
        } // addDefaultCtxtMenu

        // This returns the top-level options as a JSON tree. TODO: Should use the RDF menu.
        var urlTopLevel = AddUrlPrefix("entity_dirmenu_only.py", "mode=menu");

		try {
			d3.json(urlTopLevel, addDefaultCtxtMenu);
		}
		catch(exc)
		{
		    // TODO : Remove this, which cannot work.
			console.log("createContextMenus caught:" + exc);
			var emptyItems = {
				"Nothing" : {
                        name: "Empty menu",
                        type: 'text'
                    }
				};

			addDefaultCtxtMenu(null, emptyItems);
		}
    }; // createContextMenus

    // When the mouse right button is down, this loads the contextual menu content into the SVG object.
    // Releasing the right button triggers the contextual menu whose content is in the SVG object.
    $("g.survol_node").mousedown(function(ev){
        // If left click, it should call entity.py.
        function getEntityUrl(error, jsonData)
        {
            console.log("getXmlMenu");
            if (error) {
                alert("getEntityUrl error=" + error + " jsonData=" + jsonData);
                return;
            }
            if (jsonData.error != undefined)
            {
                alert("Error:" + jsonData.error);
                return;
            }

            // This tests of it is a Json object by comparing the constructors.
            if ( !isJson(jsonData)) {
                alert("Should be a Json object : " + typeof(jsonData));
            }

            // FIXME: This does not seem to work when called from Android.
            // TODO: It could be cleaner to store the promise in defer_scripts.
            //       This, because WSGI calculates it much earlier than CGI.
            //       If this is not resolved, we may just need to give it as is to contextMenu.
            objectThis.__data__.defer_scripts.resolve(jsonData);
        }

        // 1 for the left button, 2 for the middle button, or 3 for the right button
        if(ev.which == 3)
        {
            var objectThis = this;

            // If this was defined from a Python script.
            if(this.__data__.survol_url) {
                console.log("Right click on URL=" + this.__data__.survol_url);
                if(this.__data__.survol_url.indexOf("entity.py") < 0) {
                    /*
                    Very special case of the execution of file_directory.py : It returns CIM_DataFile and
                    CIM_Directory, but also links to file_directory.py with the entity type CIM_Directory.
                    So these nodes become also clickable.
                    */
                    console.log("Should not happen: only entity.py is clickable");
                    return;
                }
                // We expect a contextual menu in JSON format, not a graph.
                // TODO: Use the RDF menu instead of Json.
                var urlEntityNoMode = this.__data__.survol_url.replace("entity.py", "entity_dirmenu_only.py")
                var urlEntity = AddUrlCgiArg(urlEntityNoMode, "mode=menu");

                console.log("urlEntity:" + urlEntity);

                this.__data__.defer_scripts = jQuery.Deferred();

                // This loads the menu options as a JSON tree.
                d3.json(urlEntity, getEntityUrl);
            }
        }
    });

    // Call function after page load: http://stackoverflow.com/questions/890090/jquery-call-function-after-load

    createContextMenus();

    myForce.restart();
    // myForce.alphaTarget(0.3).restart();
} // displayD3Layout

