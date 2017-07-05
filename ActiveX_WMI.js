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
This returns a WQL query like 'select * from Win32_Process where Handle="12345"'
*/
function UrlToWQL(strClass,dictProperties)
{
	console.log("UrlToWQL: strClass="+strClass);

	queryWQL = "select * from " + strClass;
	queryDelim = " where ";

	for( keyProp in dictProperties) {
		var valProp = dictProperties[keyProp];
		queryWQL += queryDelim + keyProp + "=" + "'" + valProp + "'";
		queryDelim = " and ";
		// console.log("UrlToWQL queryWQL="+queryWQL);
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
function ActiveX_WMI_Data(svcWbem,wqlQuery)
{
	var coll = svcWbem.ExecQuery(wqlQuery);
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
		//console.log("=========== " + objWmi.Name);

		var objDict = {};

		// https://stackoverflow.com/questions/973016/jscript-enumerator-and-list-of-properties
		var colProps = new Enumerator(objWmi.Properties_);
		for ( ; !colProps.atEnd(); colProps.moveNext()) { 
			//console.log("Before item:");
			var propWmi = colProps.item();
			//console.log("After item:");
			//console.log("Name:"+propWmi.Name);
			var typVal = typeof propWmi.Value;
			if ( (typVal === "string") ||(typVal === "boolean") ||(typVal === "number") ) {
				//console.log("    "+propWmi.Name + ": " + propWmi.Value);
				objDict[propWmi.Name] = propWmi.Value;
			} else if (typVal === "object") {
				var strObj = ObjectToString(propWmi.Value);
				//console.log("    "+propWmi.Name + ": " + "object:" + strObj);
				objDict[propWmi.Name] = strObj;
			} else {
				//console.log("    "+propWmi.Name + ": " + " Unknown type");
				objDict[propWmi.Name] = "Unknown "+typVal;
			}
			//console.log("After:");
		}
		dictObjects[objWmi.Name] = objDict;
		items.moveNext();
	}

	console.log("ActiveX_WMI_Data leaving");
	return dictObjects;
} // ActiveX_WMI_Data

/* This returns a dictionary of objects indexed by their WMI name.
Here, we should normally expect at most one object.
This build a menu whose structure depends on the number of objects, for clarity.
After that, one just needs to append it to contextMenu object:
"https://swisnl.github.io/jQuery-contextMenu/dist/jquery.contextMenu.js" */
function ActiveX_WMI_ConvertObjToMenuItems(dictObjects)
{
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

				// Is it really used ??? Why this icon ??
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
		}
	}

	return menusActiveX;
} // ActiveX_WMI_ConvertObjToMenuItems

/*
Si le xid est de la forme "machineXXX@classe.p1=v1,p2=v2" alors on va interroger machineXXX.

Et, s'il est de la forme "CIM_ComputerSystem.Name=machineXXX", meme chose.
Mais on pourrait peut-etre trouver des infos sur le WMI courant ... Oui ?

En theorie, il pourrait y avoir d'autres cas. Est-ce qu'on retourne une seule liste en vrac ?
A priori oui, pour simplifier, mais on peut prefixer les labels ?
*/
function SplitRemoteXid(objUrl)
{
	var strXid = "?xid=";
	var posQuestMark = objUrl.indexOf(strXid);
	if( posQuestMark < 0)
	{
		console.log("SplitRemoteXid: No XID in URL");
		return null;
	}

	var strXid = objUrl.substr(posQuestMark + strXid.length);
	console.log("SplitRemoteXid: strXid="+strXid);

	var posDot = strXid.indexOf(".");
	if(posDot == -1)
	{
		return null;
	}

	var strClass = strXid.substr(0,posDot);
	// console.log("strClass="+strClass);

	var strProperties = strXid.substr(posDot+1);
	// console.log("strProperties="+strProperties);

	// The properties here, can only be unique.
	dictProperties = {}

	var arrProperties = strProperties.split(",");

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
		dictProperties[kvSplit[0]] = kvSplit[1];
	}

	// TODO: Extract a possible machine name from the XID before the arrobas "@".
	return {
		m_remote_machine: "",
		m_class: strClass,
		m_dict_properties: dictProperties
	};
}

// This tells if this is the host where the brwoser is running.
function IsBrowserHostname(hostNam)
{
	//return true;
	// NO, THIS DOES NOT WORK.
	var isLocal = (hostNam == "localhost") || (hostNam == "127.0.0.1") || (hostNam == "");
	console.log("IsBrowserHostname hostNam="+hostNam+" isLocal="+isLocal);
	return isLocal;
}

/*
This contains a lot of information about the library contextMenu.
https://github.layalk.net/jQuery-contextMenu/docs.html
*/

/* This contains user/pass for each WMI hostname. */
var globalCredentials = {
	"HostTest" : { stored_username: "UsrN", stored_password: "Pswd" }
};

function GetUserPass(hostName)
{
	//	RECALL USERPASS FOR THE MACHINE
	//	$.contextMenu.xyz InputValues(options, $this.data());

	// To fill input commands with values from a map:
	 // $.contextMenu.getInputValues(opt, {m_username: "foo", m_password: "bar"});

	console.log("GetUserPass hostName="+hostName+" globalCredentials="+ObjectToString(globalCredentials));
	var userPass = globalCredentials[hostName];

	return {
		m_user:"rchateauneu@hotmail.com",
		m_pass: "troulala" };
}

/* This returns an object which can be called to create a connection to Wbem:
	objwbemServices = .ConnectServer( _
	  [ ByVal strServer ], _
	  [ ByVal strNamespace ], _
	  [ ByVal strUser ], _
	  [ ByVal strPassword ], _
	  [ ByVal strLocale ], _
	  [ ByVal strAuthority ], _
	  [ ByVal iSecurityFlags ], _
	  [ ByVal objwbemNamedValueSet ] _
	)
	*/
function CreateWbemConnector(hostName){
	console.log("CreateWbemConnector hostName="+hostName);
	return {
		m_hostLocat: hostName,
		m_funcLocat: function() {
			// This object is a Microsoft extension and is supported in Internet Explorer only,
			// not in Windows 8.x Store apps.
			var wbemLocat = new ActiveXObject("WbemScripting.SWbemLocator");

			if(hostName == ".") {
				return wbemLocat.ConnectServer(".", "root\\cimv2" );
			} else {
				var userPass = GetUserPass(hostName);
				return wbemLocat.ConnectServer(hostName, "root\\cimv2", userPass.m_user, userPass.m_pass);
			}
		}
	};
} // CreateWbemConnector

// Depending on the object parameters, this chooses the connector to Wbem.
function ConnectWbemServer(hostName, strClass, dictProperties)
{
	console.log("ConnectWbemServer hostName="+hostName+" strClass="+strClass);

	// If a machine name given in the XID before "@".
	if(hostName != "" ) {
		console.log("ConnectWbemServer: WMI connect to explicit hostName:"+hostName);
		return CreateWbemConnector(hostName);
		// svcWbem = wbemLocat.ConnectServer(hostName, "root\\cimv2", "rchateauneu@hotmail.com", "troulala");
	}

	// Possibly other cases depending on the class name.
	var wmiHostname = dictProperties["Name"];
	console.log("ConnectWbemServer: strClass="+strClass+" wmiHostname="+wmiHostname);
	if( ( strClass == "CIM_ComputerSystem") && ( ! IsBrowserHostname(wmiHostname) ))
	{
		var remoteHostname = dictProperties["Name"];
		console.log("ConnectWbemServer: WMI connect to CIM_ComputerSystem remoteHostname="+remoteHostname);
		return CreateWbemConnector(remoteHostname);
		// svcWbem = wbemLocat.ConnectServer(wmiHostname, "root\\cimv2", "rchateauneu@hotmail.com", "troulala");
	}

	console.log("ConnectWbemServer: WMI connect local");
	return CreateWbemConnector(".");
	//svcWbem = wbemLocat.ConnectServer(".", "root\\cimv2");
	//return svcWbem;
}


function ActiveX_WMI_JContextMenu(objUrl)
{
	// IE and Windows only.
	if( ! isIEorEDGE())
	{
		// console.log("ActiveX_WMI_JContextMenu Not IE");
		return {};
	}
	// console.log("ActiveX_WMI_Data IE");

	console.log("ActiveX_WMI_JContextMenu objUrl="+objUrl);

	var remoteXid = SplitRemoteXid(objUrl);
	if( remoteXid == null)
	{
		return {};
	}

	var wqlQuery = UrlToWQL(remoteXid.m_class,remoteXid.m_dict_properties);
	if(wqlQuery == "")
	{
		return {};
	}
	console.log("ActiveX_WMI_JContextMenu wqlQuery="+wqlQuery);

	var TheFullSubItems = {};

	var svcWbemObject = ConnectWbemServer(remoteXid.m_remote_machine,remoteXid.m_class,remoteXid.m_dict_properties);
	try {
		svcWbem = svcWbemObject.m_funcLocat();

		// var svcWbem = ConnectWbemServer(remoteXid.m_remote_machine,remoteXid.m_class,remoteXid.m_dict_properties);
		var dictObjects = ActiveX_WMI_Data(svcWbem,wqlQuery);

		var TheItemsSuiteActiveXSubItems = ActiveX_WMI_ConvertObjToMenuItems(dictObjects);

		jQuery.extend(TheFullSubItems,TheItemsSuiteActiveXSubItems);
	}
	catch(excep)
	{
		// Cannot connect.
		console.log("ActiveX_WMI_JContextMenu caught:" + excep);
	}


	// if( remoteXid.m_remote_machine != "" )
	/* Only if CIM_ComputerSystem, or if this xid indicates a remote machine,
	 then asks for username and password.*/
	if( typeof svcWbemObject.m_hostLocat != ".")
	{
		console.log("Editing username and password for m_hostLocat="+svcWbemObject.m_hostLocat);
		// To fill input commands with values from a map:
		// $.contextMenu.getInputValues(options, {remote_user: "foo", remote_pass: "bar"});


		// $.contextMenu.xyz InputValues(options, $this.data());


		var TheItemsUserPassSub = {
			"remote_user": {
				name: "Username",
				type: 'text',
				value: ""
			},
			"remote_pass": {
				name: "Password",
				type: 'text',
				value: ""
			},
			"submit": {
				name: "Enter",
				callback: function(key, options) {
						/* The runtime options are passed to most callbacks on registration. giving
						the ability to access DOM elements and configuration dynamically.
						One way of using these in in the general callback when an item is clicked.
						Example:
						callback: function(itemKey, opt){
							// Alert the classes on the item that was clicked.
							alert(opt.$node.attr('class'));
							// Alert "welcome!"
							alert(opt.inputs[itemsKey].$input.val());
						}
						*/
						console.log("key="+key);
						var $this = this;

						/* "getInputValues(opt, $this.data());" saves values from input commands to data-attributes,
						but this is not what we want. Rather, this fetches values from input commands: */

						//var inpValues = $.contextMenu.setInputValues(options);
						//console.log("inpValues="+inpValues);

						$.contextMenu.getInputValues(options, this.data());
						console.log("this.data()="+ObjectToString(this.data()));
						var remUser = this.data().remote_user;
						var remPass = this.data().remote_pass;

						globalCredentials[svcWbemObject.m_hostLocat] = {
							"stored_remote_user" : remUser,
							"stored_remote_pass" : remPass,
						};
						console.log("globalCredentials="+ObjectToString(globalCredentials));

					}
			}
		};
		var TheItemsUserPass =
		{
			"ActiveXObjectWMI": {
				"name": "ActiveX Authentication",
				"items": TheItemsUserPassSub
			}
		};
		jQuery.extend(TheFullSubItems,TheItemsUserPass);
    }

	var TheItemsSuiteActiveX =
	{
		"ActiveXObjectWMI": {
			"name": "ActiveX WMI",
			"items": TheFullSubItems
		}
	};

	return TheItemsSuiteActiveX;
} // ActiveX_WMI_JContextMenu

// This returns a network compatible with D3.
// It cannot be generalised for all classes.
function GlobalMenu_CIM_Process()
{
	console.log("GlobalMenu_CIM_Process entering");

	var svcWbemObject = ConnectWbemServer("", "CIM_Process", {} );

	try {
		svcWbem = svcWbemObject.m_funcLocat();

		var wqlQuery = UrlToWQL("CIM_Process", {});
		var dictObjects = ActiveX_WMI_Data(svcWbem,wqlQuery);
	}
	catch(excep)
	{
		// Cannot connect.
		console.log("ActiveX_WMI_JContextMenu caught:" + excep);
		return {
			"nodes": [],
			"links": []
		};
	}

	console.log("GlobalMenu_CIM_Process Creating graph");
	
	var netNodes = [];
	var pidTOidx = {};
	
	// One item per object.
	var idxObj = 0;
	for( var keyObj in dictObjects) {
		var oneObj = dictObjects[keyObj];
		var procId = oneObj["ProcessId"];
		pidTOidx[procId] = idxObj;
		//console.log("oneObj procId="+procId+" keyObj="+keyObj+" idxObj="+idxObj);
		
		// This member is mandatory for D3.
		oneObj["name"] = oneObj["Caption"];
		oneObj["type"] = 3; // Temporary hard-code.
		oneObj["fill"] = "#FF7147" ;
		oneObj["entity_class"] = "CIM_ComputerSystem";
		// This is necessary otherwise cannot merge.
		oneObj["survol_url"] = "http://127.0.0.1:8000/htbin/entity.py?xid=CIM_Process.Handle=" + procId;

		netNodes[idxObj] = oneObj;
		idxObj++;
	}
		
	var netLinks = [];

	// Now creates the links.
	for( var idxNod in netNodes) {
		var oneNod = netNodes[idxNod];
		var prntProcId = oneNod["ParentProcessId"];
		var idxPrntPid = pidTOidx[prntProcId];
		if( idxPrntPid) {
			// console.log("oneNod prntProcId="+prntProcId+" idxPrntPid="+idxPrntPid);
			netLinks.push( {
				source: parseInt(idxNod),
				target: idxPrntPid,
				link_prop: "Sub-process",
				value: 10 // This is a temporary hard-code.
				});
			//console.log("Inserted idxPrntPid"+idxPrntPid);
		}
	}
		
	console.log("GlobalMenu_CIM_Process leaving");
	return {
		"nodes": netNodes,
		"links": netLinks
	};
} // GlobalMenu_CIM_Process

function ActiveX_WMI_JCtxtMenuGlobal( funcD3Displayer )
{
	// IE and Windows only.
	if( ! isIEorEDGE())
	{
		// console.log("ActiveX_WMI_JCtxtMenuGlobal Not IE");
		return {};
	}
	// console.log("ActiveX_WMI_JCtxtMenuGlobal IE");
	
	var globCtxtMenu = 
	{
		"theFirst": {
			name: "Local processes",
			callback: function(key, options) {
				
					/////     D ABORD CACHER LE MENU
				
					var data = GlobalMenu_CIM_Process();
					console.log("data.nodes="+data.nodes.length+" data.links="+data.links.length);
					funcD3Displayer(data);
				}
		}
	};

	return globCtxtMenu;
} // ActiveX_WMI_JCtxtMenuGlobal

/* This returns a menu made of a WMI query, ... the associations !! */
function ActiveX_WMI_JContextMenuLocal()
{
	console.log("Not implemented yet");
	console.log("Not implemented yet");
	console.log("Not implemented yet");
	console.log("Not implemented yet");
	return [];
}

