import pywbem
import urllib
import sys
import lib_credentials

try:
    # Python2
	from urlparse import urlparse
except ImportError:
    # Python3
	from urllib.parse import urlparse


# url="http://google.com"

def GetMyCookie(url):
    request = urllib.request(url)
    sock=urllib.request.urlopen(request)
    try:
        cookies=sock.info()['Set-Cookie']
    except KeyError:
        print("No cookie key")
        return
    content=sock.read()
    sock.close()
    print (cookies, content)

def sendResponse(url,cookies):
    request = urllib.Request(url)
    request.add_header("Cookie", cookies)
    request.add_data(urllib.urlencode([('arg1','val1'),('arg1','val1')]))
    opener=urllib.build_opener(urllib.HTTPHandler(debuglevel=1))
    sock=opener.open(request)
    content=sock.read()
    sock.close()
    print( len(content) )



"""


import cookielib
import urllib2

cookies = cookielib.LWPCookieJar()
handlers = [
    urllib2.HTTPHandler(),
    urllib2.HTTPSHandler(),
    urllib2.HTTPCookieProcessor(cookies)
    ]
opener = urllib2.build_opener(*handlers)

def fetch(uri):
    req = urllib2.Request(uri)
    return opener.open(req)

def dump():
    for cookie in cookies:
        print cookie.name, cookie.value

uri = 'http://www.google.com/'
res = fetch(uri)
dump()

# save cookies to disk. you can load them with cookies.load() as well.
#cookies.save('mycookies.txt')
"""

# Possibly process cookies.
def Headers():
    print("""Content-Type: text/html
""")

def TestCookie(url):
    print("Testing coolies<br>")
    GetMyCookie(url)
    sendResponse(url,{"aaa":"bbb"} )


def ThrowException(msg):
    Headers()

    print("""<html>
    <head></head>
    <body>
    """)

    print("Error="+msg+"<br>")

    print("""</body>
    </html>
    """)

    raise


# A la maison seulement
# conn2 = pywbem.WBEMConnection('http://192.168.1.88',  ('pegasus', 'toto'))

def WbemConnection(cgiUrl):
    try:
        # TODO Stocker ca dans les cookies.
        #if cgiUrl == "http://127.0.0.1":
        #    creden = ('', '')
        #elif cgiUrl == "http://192.168.1.88":
        #    creden = ('pegasus', 'toto')
        #else:
        #    creden = ('', '')
        creden = lib_credentials.GetCredentials( "WBEM", cgiUrl )

        # ATTENTION: Si probleme de connection, on ne le voit pas ici mais
        # au moment du veritable acces.
        conn = pywbem.WBEMConnection(cgiUrl , creden )
    except Exception:
        exc = sys.exc_info()[1]

        ThrowException("cgiUrl="+cgiUrl+" Caught:"+str(exc)+"<br>")

    # TestCookie(url)
    return conn


# GetMyCookie("http://127.0.0.1")


def PrintObjToHtml(obj,horiz=True):
    # print("Type="+str(type(obj))+":")
    if isinstance(obj,dict):
        print("<table border='1'>")
        for inst in obj:
            print("<tr>")
            print("<td>"+str(inst)+"</td>")
            print("<td>")
            PrintObjToHtml(obj[inst],not horiz)
            print("</td>")
            print("</tr>")
        print("</table>")
    elif isinstance(obj,(list,set,tuple)):
        print("<table border='1'>")
        if horiz:
            print("<tr>")
            for inst in obj:
                print("<td>")
                PrintObjToHtml(inst,not horiz)
                print("</td>")
            print("</tr>")
        else:
            for inst in obj:
                print("<tr>")
                print("<td>")
                PrintObjToHtml(inst,not horiz)
                print("</td>")
                print("</tr>")
        print("</table>")
    else:
        print(str(obj))


################################################################################

# Il y a de la duplication la-dedans.
# On fera du menage.

def NamespacesEnumeration(conn):
    """
	Different brokers have different CIM classes, that can be used to
	enumerate namespaces. And those may be nested under miscellaneous
	namespaces. This method tries all known combinations and returns
	first non-empy list of namespace instance names.
	@return (interopns, nsclass, nsinsts)
	where
		interopns is a instance name of namespace holding namespace CIM
			class
		nsclass is a name of class used to enumerate namespaces
		nsinsts is a list of all instance names of nsclass
	"""
    nsclasses = ['CIM_Namespace', '__Namespace']
    namespaces = ['root/cimv2', 'Interop', 'interop', 'root', 'root/interop']
    interopns = None
    nsclass = None
    nsinsts = []
    for icls in range(len(nsclasses)):
        for ins in range(len(namespaces)):
            try:
                nsins = namespaces[ins]
                nsinsts = conn.EnumerateInstanceNames(nsclasses[icls], namespace=nsins)
                interopns = nsins
                nsclass = nsclasses[icls]
            except Exception:
                exc = sys.exc_info()[1]
                arg = exc.args
                if arg[0] in [pywbem.CIM_ERR_INVALID_NAMESPACE,
                              pywbem.CIM_ERR_NOT_SUPPORTED,
                              pywbem.CIM_ERR_INVALID_CLASS]:
                    continue
                else:
                    raise
            if len(nsinsts) > 0:
                break
    return (interopns, nsclass, nsinsts)

def EnumNamespacesCapabilities(conn):
    interopns, _, nsinsts = NamespacesEnumeration(conn)

    nslist = [inst['Name'].strip('/') for inst in nsinsts]
    if interopns not in nslist:
        # Pegasus didn't get the memo that namespaces aren't hierarchical.
        # This will fall apart if there exists a namespace <interopns>/<interopns>.
        # Maybe we should check the Server: HTTP header instead.
        nslist = [interopns + '/' + subns for subns in nslist]
        nslist.append(interopns)

    nslist.sort()
    if 'root/PG_InterOp' in nslist or 'root/interop' in nslist:
        nsd = dict([(x, 0) for x in nslist])
        # Bizarrement, ca renvoie zero pour 'root/PG_InterOp' alors que
        # la classe 'PG_ProviderCapabilities' a des instances ?
        # Peut-etre que c'est hard-code, qu'il n'y a pas besoin de provider pour cette classe ?
        caps = conn.EnumerateInstances('PG_ProviderCapabilities',
                                       namespace='root/PG_InterOp' if 'root/PG_InterOp' in nslist else 'root/interop',
                                       PropertyList=['Namespaces'])
        for cap in caps:
            for _ns in cap['Namespaces']:
                try:
                    nsd[_ns] += 1
                except KeyError:
                    pass
    else:
        nsd = {}
    return nsd

# For debugging only
def PrintCapabilitiesForInstrumentation(conn):
    caps = None
    last_error = AssertionError("No interop namespace found")
    for interopns in ('root/PG_InterOp', 'root/interop'):
        try:
            caps = conn.EnumerateInstances(
                            ClassName='PG_ProviderCapabilities',
                            namespace=interopns,
                            PropertyList=['Namespaces', 'ClassName'])
            break
        except pywbem.CIMError as err:
            # TODO Python 3
            if err.args[0] != pywbem.CIM_ERR_INVALID_NAMESPACE:
                raise
            last_error = err
    else:
        raise last_error
    print("<br><table border=1>")
    for cap in caps:
        print("<tr>")
        print("<td>"+str(cap.classname)+"</td>")
        print("<td>"+str(cap.path)+"</td>")
        # print("<td>"+str(cap.namespace)+"</td>")
        print("<td>"+str(cap['ClassName'])+"</td>")
        print("<td>"+str(cap)+"</td>")
        print("<td>")
        print("<table border=1 bgcolor='#00FF00'>")
        for x,y in cap.iteritems():
            print("<tr>")
            print("<td>"+str(x)+"</td>")
            print("<td>"+str(y)+"</td>")
            print("</tr>")
        print("</table>")
        print("</td>")
        print("</tr>")
    print("</table><br>")

# They can belong to several namespaces.
def GetCapabilitiesForInstrumentation(conn,namSpac):
    caps = None
    last_error = AssertionError("No interop namespace found")
    for interopns in ('root/PG_InterOp', 'root/interop'):
        try:
            caps = conn.EnumerateInstances(
                            ClassName='PG_ProviderCapabilities',
                            namespace=interopns,
                            PropertyList=['Namespaces', 'ClassName'])
            break
        except pywbem.CIMError as err:
            # TODO Python 3
            if err.args[0] != pywbem.CIM_ERR_INVALID_NAMESPACE:
                raise
            last_error = err
    else:
        raise last_error
    resu = []
    for cap in caps:
        if namSpac in cap['Namespaces']:
            resu.append( cap['ClassName'])
    return resu

################################################################################
# Selectionner des objects et des classes de WMI sans passer par WBEM
# ou le WmiMapper. Ca ne nous empeche pas de le faire par la suite.

# Il faudra aussi explorer les clients WMI comme on le fait avec SLP.

# Il faut pouvoir identifier des objets qui sont des classes differentes
# mais de meme classe de base, et avec des proprietes identiques.
# Ou tout au moins que la classe de l'un soit derivee de la classe de l'autre.


################################################################################

def UrlNamespace(namspac, cgiUrl, instrumented):
    if instrumented:
        return "EnumClassNamesInstrumented.py?ns=" + namspac + "&url=" + cgiUrl
    else:
        return "EnumClassNames.py?ns=" + namspac + "&url=" + cgiUrl

def HrefNamespace(namspac, cgiUrl):
    if namspac is None:
        return ""
    return "<a href='" + UrlNamespace(namspac, cgiUrl, False) + "'>" + namspac + "</a>"

def HrefNamespaceInstrumented(namspac, cgiUrl):
    if namspac is None:
        return ""
    return "<a href='" + UrlNamespace(namspac, cgiUrl, True) + "'>" + namspac + "</a>"

def UrlClassName(topclass, theNamSpac, cgiUrl):
    return "EnumInstanceNames.py?classname=" + topclass + "&ns=" + theNamSpac + "&url=" + cgiUrl

def HrefClassName(topclass, theNamSpac, cgiUrl):
    if topclass is None:
        return ""
    return "<a href='" + UrlClassName(topclass, theNamSpac, cgiUrl) + "'>" + topclass + "</a>"

