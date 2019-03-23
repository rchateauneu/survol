#!/usr/bin/python

"""
Edits credentials Survol parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import os
import sys
import cgi
import socket
import lib_common
import lib_util
import lib_credentials
import lib_export_html
import lib_exports
from lib_util import WrtAsUtf


# This lists the content of credentials and associates a variable name to each element.
# This variable name which must be unique, is later used to build a HTML form.
def CreateCredentialsMap():
    credTypeList = lib_credentials.GetCredentialsTypes()

    credTypesDict = dict()

    for credType in sorted(credTypeList):

        credTypesDict[credType] = dict()

        # This is a homogeneous list, for example of machines names, or databases.
        credNams = lib_credentials.GetCredentialsNames( credType )

        for credName in sorted(credNams):

            cred = lib_credentials.GetCredentials( credType, credName )

            credInputPrefix = credType + "_" + credName + "_" + cred[0]
            credInputPassword = credInputPrefix + "_UPDATE_PASSWORD"
            credInputNameDel = credInputPrefix + "_DELETE_CREDENTIAL"

            credNameUrl = CredTypeNameToUrl(credType, credName)

            credTypesDict[credType][credName] = [cred[0],cred[1],credInputPassword,credInputNameDel,credNameUrl]

    return credTypesDict

# This applies only if the jinja2 module is not there.
def FormUpdateCredentialsNoJinja(formAction,credMap):
    WrtAsUtf("""
    <form method="post" action="%s" name="ServerCredentials">
    """%(formAction))

    WrtAsUtf("""<tr>
    <td><b>Resource</b></td>
    <td><b>Account</b></td>
    <td><b>Password</b></td>
    <td><b>Del</b></td>
    </tr>
    """)

    for credType in sorted(credMap):
        # This is a type of access: Oracle databse, Linux machine, Windows account etc...
        WrtAsUtf("<tr><td colspan=4><b>%s</b></td></tr>" % (credType))

        # This is a homogeneous list, for example of machines names, or databases.
        credNams = credMap[ credType ]
        for credName in sorted(credNams):
            # For a machine, this accepts only one user.
            # Same for a given database: Only one user. The reason is that the scripts
            # do not have to chosse when they need to display information about something.
            # Read-only access rights are enough.
            cred = credNams[credName]

            credNameUrl = cred[4]

            if credNameUrl:
                WrtAsUtf("""<tr>
                <td><a href="%s">%s</a></td>
                <td>%s</td>
                <td><input name="%s" value="%s"></td>
                <td><input type="checkbox" name="%s"></td>
                </tr>
                """%(credNameUrl,credName,cred[0],cred[2],cred[1],cred[3]))
            else:
                # If no URL can be created. For example of the map misses a function
                # for a given credential type.
                WrtAsUtf("""<tr>
                <td>%s</td>
                <td>%s</td>
                <td><input name="%s" value="%s"></td>
                <td><input type="checkbox" name="%s"></td>
                </tr>
                """%(credName,cred[0],cred[2],cred[1],cred[3]))

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4>""")
    WrtAsUtf("""
    <input value="Update / delete credential" name="SubmitCredUpdName" type="submit"><br>
    """)
    WrtAsUtf("""</td>""")
    WrtAsUtf("""</tr>""")
    WrtAsUtf("""
    </form>
    """)

def FormInsertCredentialsNoJinja(formAction,credTypeList):
    WrtAsUtf("""
    <form method="post" action="edit_credentials.py" name="ServerCredentials">
    """)

    credInputAddPrefix = "credentials_add_"
    credInputAddType = credInputAddPrefix + "type"
    credInputAddName = credInputAddPrefix + "name"
    credInputAddUsr = credInputAddPrefix + "usr"
    credInputAddPwd = credInputAddPrefix + "pwd"

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4><b>Credentials creation</b></td>""")
    WrtAsUtf("""</tr>""")

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4><select name="%s">"""%(credInputAddType))
    for credType in credTypeList:
        WrtAsUtf("""<option value='%s'>%s</option>""" % (credType, credType ))
    WrtAsUtf("""</select></td>""")
    WrtAsUtf("""</tr>""")

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""
    <td><input name="%s"></td>
    <td><input name="%s"></td>
    <td><input name="%s"></td>
    </tr>
    """ % (credInputAddName,credInputAddUsr,credInputAddPwd))

    WrtAsUtf("""<tr>""")
    WrtAsUtf("""<td colspan=4>""")
    WrtAsUtf("""
    <input type="hidden" value="HiddenValue" name="HiddenName">
    <input value="Insert new credential" name="SubmitCredAddName" type="submit">
    """)
    WrtAsUtf("""</td>""")
    WrtAsUtf("""</tr>""")
    WrtAsUtf("""
    </form>
    """)

def InsertedCredMap(cgiArguments):
    # This is called if the form tries to insert a new credential
    try:
        cgiArguments["SubmitCredAddName"]
        credType = cgiArguments["credentials_add_type"].value
        credName = cgiArguments["credentials_add_name"].value
        credUsr = cgiArguments["credentials_add_usr"].value
        credPwd = cgiArguments["credentials_add_pwd"].value

        lib_credentials.AddCredential(credType,credName,credUsr,credPwd)

    except KeyError:
        pass

def UpdatedCredMap(cgiArguments):
    """
    This takes the list on input cgi variables and uses it to update the passwords
    or delete entire rows of credentials (user+pass).
    """
    credMap = CreateCredentialsMap()

    credMapOut = dict()

    # Writes to the output file only if the credentials are really changed.
    wasChanged = False
    try:
        cgiArguments["SubmitCredUpdName"]

        for credType in sorted(credMap):
            # WrtAsUtf("credType=%s<br>"%credType)
            credMapOut[credType] = dict()
            credNams = credMap[credType]
            for credName in sorted(credNams):
                cred = credNams[credName]
                # WrtAsUtf("cred=%s<br>"%str(cred))

                try:
                    # If the "_del" variable is ticked, do not copy the credentials.
                    cgiArguments[cred[3]]
                    wasChanged = True
                    continue
                except:
                    pass

                try:
                    # If the "_upd" variable is ticked, copy the credentials with a new password.
                    # BEWARE / TODO / FIXME: If the password is empty, it is not taken into account.
                    # It does not seem possible to have an empty password.
                    updPassword = cgiArguments[cred[2]].value
                    if updPassword != cred[1]:
                        wasChanged = True
                        #   WrtAsUtf("Name=%s: Replace %s by %s<br>"%(cred[0],cred[1],updPassword))
                        cred[1] = updPassword
                except:
                    pass

                credMapOut[credType][credName] = cred
                # WrtAsUtf("Added cred=%s<br>"%str(cred))

    except KeyError:
        # WrtAsUtf("No upd nor del<br>")
        credMapOut = credMap
        pass

    if wasChanged:
        # Change the file only if something really changed.
        lib_credentials.UpdatesCredentials(credMapOut)
    return credMapOut


def CredDefinitions():
    """
    This returns the list of known credential types and for each of them,
    a function which creates a URL for a credential resource name.
    """

    def CredUrlLogin(credName_Machine):
        """ Return a node given a machine name"""
        # Example: credName_Machine="titi\\rchateauneu@hotmail.com"
        serverNode = lib_common.gUriGen.HostnameUri(credName_Machine)
        return serverNode

    def CredUrlWMI(hostname):
        nodeWmi = lib_util.UrlPortalWmi(hostname)
        return nodeWmi

    def CredUrlOracle(dbName):
        # Example: dbName = "XE", which must be defined in tnsnames-ora
        from sources_types.oracle import db as oracle_db
        node_oradb = oracle_db.MakeUri( dbName )
        return node_oradb

    def CredUrlSqlExpress(dbName):
        # Example: dbName = "RCHATEAU-HP\\SQLEXPRESS". It contains the server name.
        # Connection with ODBC.
        # conn = pyodbc.connect('DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;DATABASE=ExpressDB;UID=essaisql;PWD=tralala')
        # The ODBC connection string can be, from Fedora Linux:
        # 'DRIVER={ODBC Driver 13 for SQL Server};SERVER=192.168.0.14;PORT=1433;DATABASE=SQLEXPRESS;UID=xxxxxxx;PWD=yyyyyyy'

        # TODO: Finish this
        return None

    def CredUrlMySql(instanceMySql):
        from sources_types.mysql import instance as survol_mysql_instance
        nodeInstance = survol_mysql_instance.MakeUri(instanceMySql)
        return nodeInstance

    def CredUrlWBEM(cimomUrl):
        # Example: urlWbem = "http://192.168.0.17:5989"
        if False:
            hostname = cimomUrl[7:]
            nodeWbem = lib_util.UrlPortalWbem(cimomUrl)
            return nodeWbem
        else:
            import lib_wbem
            theCimom = lib_credentials.KeyUrlCgiEncode(cimomUrl)
            nodeWbem = lib_wbem.WbemAllNamespacesUrl(theCimom)
            return nodeWbem

    def CredUrlSurvol(survolUrl):
        nodeSurvol = lib_common.NodeUrl(survolUrl)
        return nodeSurvol

    def CredUrlRabbitMQ(configNam):
        from sources_types.rabbitmq import manager as survol_rabbitmq_manager
        nodeManager = survol_rabbitmq_manager.MakeUri(configNam)
        return nodeManager

    def CredUrlAzure(subscriptionName):
        # Example: subscriptionName = "Visual Studio Professional"
        from sources_types.Azure import subscription as azure_subscription
        subscriptionNode = azure_subscription.MakeUri( subscriptionName )
        return subscriptionNode

    def CredUrlODBC(dsn):
        from sources_types.odbc import dsn as survol_odbc_dsn
        nodeDsn = survol_odbc_dsn.MakeUri( "DSN=" + dsn )
        return nodeDsn

    # This hard-coded list allows also to create credentials for the first time.
    credTypesWellKnown = {
        "Login" : CredUrlLogin,
        "WMI" : CredUrlWMI,
        "Oracle" : CredUrlOracle,
        "SqlExpress" : CredUrlSqlExpress,
        "MySql" : CredUrlMySql,
        "WBEM" : CredUrlWBEM,
        "Survol" : CredUrlSurvol,
        "RabbitMQ" : CredUrlRabbitMQ,
        "Azure" : CredUrlAzure,
        "ODBC" : CredUrlODBC,
    }

    return credTypesWellKnown

def CredTypeNameToUrl(credType,credName):
    try:
        # Maybe we can create a URL for a credName of a given credType.
        # For example a machine name if 'Login', a database if 'Oracle',
        # an access to a WBEM server if 'WBEM' etc...
        nodeGenerator = CredDefinitions()[credType]
        credNameUrl = nodeGenerator(credName)
    except:
        # Maybe the key is not defined ...
        # ... or the generator does not work
        exc = sys.exc_info()[1]
        WARNING("nodeGenerator exception:%s",str(exc))
        credNameUrl = None
    return credNameUrl

try:
    # This is a HTML template engine.
    import jinja2
except ImportError:
    jinja2 = None

def Main():
    formAction = os.environ['SCRIPT_NAME']

    cgiArguments = cgi.FieldStorage()

    credFilename = os.path.normpath(lib_credentials.CredFilNam())
    page_title = "Edit Survol credentials in %s" % credFilename

    # Hostname=Unknown-30-b5-c2-02-0c-b5-2.home
    # Host address=192.168.0.17
    # Remote client=82.45.12.63

    currHostNam = socket.gethostname()
    currHostAddr = lib_util.GlobalGetHostByName(currHostNam)
    addrRemote = os.environ['REMOTE_ADDR']

    if addrRemote not in ["82.45.12.63","192.168.0.14","127.0.0.1"]:
        lib_common.ErrorMessageHtml("Access forbidden from %s"% addrRemote )

    InsertedCredMap(cgiArguments)
    credMap = UpdatedCredMap(cgiArguments)
    credTypesWellKnown = CredDefinitions()
    credTypeList=sorted(credTypesWellKnown.keys())

    if jinja2:
        MainJinja(page_title,currHostNam,currHostAddr,addrRemote,credMap,formAction,credTypeList)
    else:
        MainNoJinja(page_title,currHostNam,currHostAddr,addrRemote,credMap,formAction,credTypeList)

# Simple HTML page if jinja2 is not installed.
def MainNoJinja(page_title,currHostNam,currHostAddr,addrRemote,credMap,formAction,credTypeList):
    lib_export_html.DisplayHtmlTextHeader(page_title)

    WrtAsUtf("""
    <body><h2>%s</h2>
    """ % page_title)

    WrtAsUtf("""
    <table border="1" width='100%%'>
    <tr><td><b>Host name</b></td><td>%s</td></tr>
    <tr><td><b>Host address</b></td><td>%s</td></tr>
    <tr><td><b>Remote address</b></td><td>%s</td></tr>
    """ %(currHostNam,currHostAddr,addrRemote))

    WrtAsUtf("""<table border="1" width='100%%'>""")
    if credMap:
        FormUpdateCredentialsNoJinja(formAction,credMap)

    FormInsertCredentialsNoJinja(formAction, credTypeList)
    WrtAsUtf("""</table>""")

    lib_export_html.DisplayHtmlTextFooter()

    WrtAsUtf("</body></html>")

def MainJinja(page_title,currHostNam,currHostAddr,addrRemote,credMap,formAction,credTypeList):
    THIS_DIR = os.path.dirname(os.path.abspath(__file__))
    template_file_name = "edit_credentials.template.htm"

    # Create the jinja2 environment.
    # Notice the use of trim_blocks, which greatly helps control whitespace.
    jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(THIS_DIR), trim_blocks=True)
    jinja_template = jinja_env.get_template(template_file_name)

    import collections

    orderedMap = collections.OrderedDict()
    for credType in sorted(credMap):
        subOrderedMap = collections.OrderedDict()
        for credNam in sorted(credMap[credType]):
            subOrderedMap[credNam] = credMap[credType][credNam]
        orderedMap[credType] = subOrderedMap

    jinja_render = jinja_template.render(
        page_title=page_title,
        currHostNam=currHostNam,
        currHostAddr=currHostAddr,
        addrRemote=addrRemote,
        credMap=orderedMap,
        credTypeList=credTypeList )
    print("Content-type: text/html\n\n")
    print( jinja_render )


if __name__ == '__main__':
    Main()
