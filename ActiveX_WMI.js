function isIEorEDGE(){
	console.log("appName="+navigator.appName+ " appVersion="+navigator.appVersion);
	if (navigator.appName == 'Microsoft Internet Explorer'){
		return true;
	}
	if(navigator.appName == "Netscape"){
		if(navigator.appVersion.indexOf('Edge') > -1)
			return true;
		if(navigator.appVersion.indexOf('Trident') > -1)
			return true;
	}
	return false;
}



/*
This returns something like "select * from Win32_Process"
*/
function UrlToWQL(objUrl)
{
	var strXid = "?xid=";
	var posQuestMark = objUrl.indexOf(strXid);
	if( posQuestMark < 0)
	{
		console.log("UrlToWQL: No XID in URL");
		return "";
	}

	var strXid = objUrl.substr(posQuestMark + strXid.length);
	console.log("UrlToWQL: strXid="+strXid);

	var posDot = strXid.indexOf(".");
	if(posDot == -1)
	{
		// console.log("No class in URL");
		return "";
	}

	var strClass = strXid.substr(0,posDot);
	// console.log("strClass="+strClass);

	var strProperties = strXid.substr(posDot+1);
	// console.log("strProperties="+strProperties);

	var arrProperties = strProperties.split(",");

	queryWQL = "select * from " + strClass;
	queryDelim = " where ";

	for (var ixProp = 0; ixProp < arrProperties.length; ixProp++) {
		// console.log("arrProperties[ixProp]="+arrProperties[ixProp]);
		var kvSplit = arrProperties[ixProp].split("=");
		// console.log("kvSplit.length="+kvSplit.length);
		if( kvSplit.length != 2 )
		{
			console.log("Key-value pair bad syntax:"+arrProperties[ixProp]);
			continue;
		}
		// console.log("kvSplit[0]="+kvSplit[0]);
		// console.log("kvSplit[1]="+kvSplit[1]);
		queryWQL += queryDelim + kvSplit[0] + "=" + "'" + kvSplit[1] + "'";
		queryDelim = " and ";
		// console.log("queryWQL="+queryWQL);
	}

	return queryWQL;
} // UrlToWQL

function ObjectToString(objDict) {
	var strObj = "";
	var delim = "";
	for (var propKey in objDict) {
		if (objDict.hasOwnProperty(propKey) ) {
			var propVal = objDict[propKey];
			propName = propKey + "=" + propVal
			// console.log("propName="+propName);
			strObj += delim + propName;

			delim = ", ";
		}
	}
	return strObj;
} // ObjectToString



/*
This returns a vector of WMI data about an object passed as an URL.
This can work on Internet Explorer and on Windows only,
and if the correct security parameters are set.

Google Chrome users can download IE Tab extension that acts as Internet Explorer emulator.
It helps enable ActiveX controls in Google Chrome as it emulates IE
by using the IE rendering engine directly within Chrome.
Firefox users can install ff-activex-host plugin to enable ActiveX controls in the browser.

https://stackoverflow.com/questions/7022568/activexobject-in-firefox-or-chrome-not-ie

objUrl="http://127.0.0.1:8000/htbin/entity.py?xid=CIM_Process.Handle=376"

The class might not exist in WMI. In this case, this returns NULL.

It returns a dictionary of objects, indexed by their WMI name.
*/
function ActiveX_WMI_Data(objUrl)
{
	console.log("ActiveX_WMI_Data objUrl="+objUrl);

	// IE and Windows only.
	if( ! isIEorEDGE())
	{
		// console.log("ActiveX_WMI_Data Not IE");
		return {};
	}
	// console.log("ActiveX_WMI_Data IE");

	var wqlQuery = 	UrlToWQL(objUrl);
	if(wqlQuery == "")
	{
		return {};
	}
	// console.log("wqlQuery="+wqlQuery);

	// This object is a Microsoft extension and is supported in Internet Explorer only,
	// not in Windows 8.x Store apps.
	// TODO: Find another location.
	var loc = new ActiveXObject("WbemScripting.SWbemLocator");

	// TODO: Set another host ?
	var svc = loc.ConnectServer(".", "root\\cimv2");
	var coll = svc.ExecQuery(wqlQuery);
	var items = new Enumerator(coll);

	console.log("Connection OK");

	/*
	Normally, it should return only one object, but we expect everything.
	TODO: There should be a time-out.
	*/
	var dictObjects = {};
	while (!items.atEnd())
	{
		var objWmi = items.item();
		
		// Some properties always exist.
		console.log("=========== " + objWmi.Name);

		var objDict = {};

		// https://stackoverflow.com/questions/973016/jscript-enumerator-and-list-of-properties
		var colProps = new Enumerator(objWmi.Properties_);
		for ( ; !colProps.atEnd(); colProps.moveNext()) { 
			var propWmi = colProps.item();
			var typVal = typeof propWmi.Value;
			if ( (typVal === "string") ||(typVal === "boolean") ||(typVal === "number") ) {
				console.log("    "+propWmi.Name + ": " + propWmi.Value);
				objDict[propWmi.Name] = propWmi.Value;
			} else if (typVal === "object") {
				var strObj = ObjectToString(propWmi.Value);
				console.log("    "+propWmi.Name + ": " + "object:" + strObj);
				objDict[propWmi.Name] = strObj;
			} else {
				console.log("    "+propWmi.Name + ": " + " Unknown type");
				objDict[propWmi.Name] = "Unknown "+typVal;
			}
		}
		dictObjects[objWmi.Name] = objDict;
		items.moveNext();
	}

	return dictObjects;
} // ActiveX_WMI_Data

/* This returns a dictionary of objects indexed by their WMI name.
Here, we should normally expect at most one object.
This build a menu whose structure depends on the number of objects, for clarity.
After that, one just needs to append it to contextMenu object:
"https://swisnl.github.io/jQuery-contextMenu/dist/jquery.contextMenu.js" */
function ActiveX_WMI_JContextMenu(objUrl)
{
	var dictObjects = ActiveX_WMI_Data(objUrl);

	var numObj = Object.keys(dictObjects).length;
	console.log("numObj="+numObj);
	if( numObj == 0 ) {
		return [];
	}

	// For each object found in a WMI table.
	function ObjDictToItem(objDict) {
		var objItem = {};

		for (var propKey in objDict) {
			if (objDict.hasOwnProperty(propKey) ) {
				var propVal = objDict[propKey];
				propName = propKey + "=" + propVal
				// console.log("propName="+propName);

				var subSubObj = { "name": propName, "icon" : "edit"}

				// { "Plik" : { "name": "aaaa", "icon" : "edit"} }
				objItem[propKey] = subSubObj;
			}
		}
		return objItem;
	} // ObjDictToItem

	// There should normally be one object only.
	menusActiveX = {};
	for (var objKey in dictObjects) {
		if (dictObjects.hasOwnProperty(objKey) ) {
			var objVal = dictObjects[objKey];

			var objSubItems = ObjDictToItem(objVal);

			var objItem = {"name": objKey, "items": objSubItems};

			menusActiveX[objKey] = objItem;
			// menusActiveX["Ze proc key"] = {"name": "Ze proc name", "items": { "Plik" : { "name": "aaaa", "icon" : "edit"} } };
		}
	}

	var TheItemsSuiteActiveX =
	{
		"ActiveXObjectWMI": {
			"name": "ActiveX WMI",
			"items": menusActiveX
		}
	};

	return TheItemsSuiteActiveX;
} // ActiveX_WMI_JContextMenu
