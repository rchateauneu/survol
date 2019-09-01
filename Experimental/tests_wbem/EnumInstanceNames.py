#!/usr/bin/env python

import sys
import cgi

# Might be pywbem or python3-pywbem.
import pywbem

import wbem_utils
import yawn_cim_insight


def UrlInstanceName(instanceName, cgiUrl):
    # return "GetInstance.py?classname=" + topclass + "&ns=" + theNamSpac + "&url=yyy"
    retUri = "GetInstance.py"\
    + "?classname=" + instanceName.classname\
    + "&ns=" + instanceName.namespace\
    + "&url=" + cgiUrl

    for key,val in instanceName.iteritems():
        if isinstance( val, pywbem.CIMInstanceName ):
            # Je me demande vraiment si ca fait partie de la clef.
            # Mais peut-etre que oui, par exemple pour faire une arborescence: Par exemple un fichier pointe vers son directory.
            # ...Dependent="//rchateau-HP/root/PG_InterOp:PG_CIMXMLCommunicationMechanism.CreationClassName=\"PG_CIMXMLCommunicationMechanism\",SystemName=\"rchateau-HP\",Name=\"PEGASUSCOMMhttp+192.168.1.83:5988\",SystemCreationClassName=\"PG_ComputerSystem\""...
            escapedVal = '"' + cgi.escape(str(val)) + '"'
            # escapedVal = cgi.escape(val)
            retUri += "&%s=%s" % ( key, escapedVal )
        else:
            escapedVal = cgi.escape(val)
            retUri += "&%s=%s" % ( key, escapedVal )
    return retUri

def HrefInstanceName(instanceName, cgiUrl):
    return "<a href='" + UrlInstanceName(instanceName, cgiUrl) + "'>" + str(instanceName) + "</a>"

arguments = cgi.FieldStorage()
className = arguments["classname"].value
nameSpace = arguments["ns"].value
cgiUrl = arguments["url"].value

conn = wbem_utils.WbemConnection(cgiUrl)

wbem_utils.Headers()

print("""<html>
<head></head>
<body>
""")

try:
    klass = conn.GetClass(className,
            namespace=nameSpace,
            LocalOnly=False,
            IncludeQualifiers=True)
except Exception:
    exc = sys.exc_info()[1]
    print("nameSpace="+nameSpace+" className="+className+". Caught:"+str(exc))
    exit(0)

print("<br>nameSpace="+nameSpace+" className="+className+"<br>")

try:
    inst_names = conn.EnumerateInstanceNames(ClassName=className,namespace=nameSpace)
except Exception:
    exc = sys.exc_info()[1]
    print("EnumerateInstanceNames nameSpace="+nameSpace+" className="+className+". Caught:"+str(exc)+"<br>")
    exit(0)

iname_dict = pywbem.NocaseDict()

for iname in inst_names:
    if iname.classname not in iname_dict:
        iname_dict[iname.classname] = [iname]
    else:
        iname_dict[iname.classname].append(iname)

print("Namespace:" + wbem_utils.HrefNamespace(nameSpace, cgiUrl) + "<br")
print("<br>Num instances="+str(len(inst_names))+"<br><br>")

print("<table border='1'>")
for iname in inst_names:
    # iname is a 'CIMInstanceName' object, made of several key-value pairs.
    print("<tr>")
    print("<td>"+iname.classname+"</td>")
    print("<td>"+iname.namespace+"</td>")
    print("<td>"+HrefInstanceName(iname, cgiUrl)+"</td>")
    print("</tr>")
print("</table>")
print("<br>")


instances = []
for cname, inames in sorted(iname_dict.items(),
        key=lambda k: k[0]):
    infos = []
    for iname in inames:
        infos.append(yawn_cim_insight.get_inst_info(iname, klass, include_all=True, keys_only=True))
    instances.append((cname, iname.namespace, infos))

wbem_utils.PrintObjToHtml(instances)

print("<br>")


print("<br>Finished")


print("""
</body>
</html>
""")
