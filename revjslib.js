/** revlibjs.js
 * Common Javascript libraries for HTML pages.
 */


function LocalHost()
{
	// return "http://127.0.0.1:2468/htbin";
	return "http://127.0.0.1/~rchateau/RevPython";
}

function RdfSources()
{
	return LocalHost() + "/internals/directory.py";
}

function SlpMenu()
{
	return LocalHost() + "/internals/gui_slpmenu.py";
}

function DynCgi()
{
	return LocalHost() + "/internals/gui_dyncgi.py";
}

// This calls GraphViz (dot) to generate a RDF file.
function RvgsToSvg()
{
	return LocalHost() + "/internals/gui_create_svg_from_several_rdfs.py";
}



