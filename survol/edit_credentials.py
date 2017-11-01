#!/usr/bin/python

"""
Edits credentials Survol parameters.
Also, it servers JSON queries from the HTML pages doing the same features, but in JSON
"""

import os
import sys
import cgi
import lib_util
import lib_credentials

def Wrt(theStr):
    sys.stdout.write(theStr)

# This list the content of credentials and assoictes a variable name to each element.
# This variable name which must be unique, is later used to build a HTML form.
# We could use the name, but this variable name must be alphanumeric.
def CreateCredentialsMap():
    credTypeList = lib_credentials.GetCredentialsTypes()
    # Wrt("credTypeList=%s<br>"%str(credTypeList))

    credTypesDict = dict()

    #counterType = 0
    for credType in sorted(credTypeList):

        credTypesDict[credType] = dict()

        # This is a homogeneous list, for example of machines names, or databases.
        credNams = lib_credentials.GetCredentialsNames( credType )

        #counterName = 0
        for credName in sorted(credNams):

            cred = lib_credentials.GetCredentials( credType, credName )

            #formVarPrefix = "var_%d_%d" % (counterCred,counterName)
            # credTypesDict[credName] = (cred[0],cred[1],formVarPrefix)
            credInputPrefix = credType + "_" + credName + "_" + cred[0]
            credInputPassword = credInputPrefix + "_UPDATE_PASSWORD"
            credInputNameDel = credInputPrefix + "_DELETE_CREDENTIAL"

            credTypesDict[credType][credName] = [cred[0],cred[1],credInputPassword,credInputNameDel]

            #counterName += 1
        #counterCred += 1
    # Wrt("credTypesDict=%s<br>"%str(credTypesDict))
    return credTypesDict



def FormUpdateCredentials(formAction,credMap):
    Wrt("""
    <form method="post" action="%s" name="ServerCredentials">
    """%(formAction))

    Wrt("""
    <table>
    """)

    Wrt("""<tr>
    <td>Resource</td>
    <td>Account</td>
    <td>Password</td>
    <td>Del</td>
    </tr>
    """)

    for credType in sorted(credMap):
        # This is a type of access: Oracle databse, Linux machine, Windows account etc...
        Wrt("<tr><td colspan=4><b>%s</b></td></tr>" % (credType))

        # This is a homogeneous list, for example of machines names, or databases.
        credNams = credMap[ credType ]
        for credName in sorted(credNams):
            # For a machine, this accepts only one user.
            # Same for a given database: Only one user. The reason is that the scripts
            # do not have to chosse when they need to display information about something.
            # Read-only access rights are enough.
            cred = credNams[credName]

            Wrt("""<tr>
            <td>%s</td>
            <td>%s</td>
            <td><input name="%s" value="%s"></td>
            <td><input type="checkbox" name="%s"></td>
            </tr>
            """%(credName,cred[0],cred[2],cred[1],cred[3]))

    Wrt("""
    </table>
    """)

    Wrt("""
    <input value="SubmitCredUpdValue" name="SubmitCredUpdName" type="submit"><br>
    </form>
    """)

def FormInsertCredentials(formAction,credTypeList):
    Wrt("""
    <form method="post" action="edit_credentials.py" name="ServerCredentials">
    """)
    Wrt("""
    <table>
    """)
    credInputAddPrefix = "credentials_add_"
    credInputAddType = credInputAddPrefix + "type"
    credInputAddName = credInputAddPrefix + "name"
    credInputAddUsr = credInputAddPrefix + "usr"
    credInputAddPwd = credInputAddPrefix + "pwd"

    Wrt("""
    <tr>""")

    Wrt("""<td>Type:<select name="%s">"""%(credInputAddType))
    for credType in credTypeList:
        Wrt("""<option value='%s'>%s</option>""" % (credType, credType ))
    Wrt("""</select></td>""")

    Wrt("""
    <td>Name:<input name="%s"></td>
    <td>User:<input name="%s"></td>
    <td>Password:<input name="%s"></td>
    </tr>
    """ % (credInputAddName,credInputAddUsr,credInputAddPwd))

    Wrt("""
    </table>
    """)

    Wrt("""
    <input type="hidden" value="HiddenValue" name="HiddenName">
    <input value="SubmitCredAddValue" name="SubmitCredAddName" type="submit">
    </form>
    """)

def InsertedCredMap(cgiArguments):
    # Maybe the form tries to insert a new cre3dential
    try:
        cgiArguments["SubmitCredAddName"]
        credType = cgiArguments["credentials_add_type"].value
        credName = cgiArguments["credentials_add_name"].value
        credUsr = cgiArguments["credentials_add_usr"].value
        credPwd = cgiArguments["credentials_add_pwd"].value

        Wrt("credentials_add_type=%s<br>"%credType)
        Wrt("credentials_add_name=%s<br>"%cgiArguments["credentials_add_name"].value)
        Wrt("credentials_add_usr=%s<br>"%cgiArguments["credentials_add_usr"].value)
        Wrt("credentials_add_pwd=%s<br>"%cgiArguments["credentials_add_pwd"].value)
        Wrt("Finished<br>")

        lib_credentials.AddCredential(credType,credName,credUsr,credPwd)

    except KeyError:
        Wrt("No add<br>")
        pass

def UpdatedCredMap(cgiArguments):
    credMap = CreateCredentialsMap()

    credMapOut = dict()

    # Writes to the output file only if the credentials are really changed.
    wasChanged = False
    try:
        cgiArguments["SubmitCredUpdName"]

        for credType in sorted(credMap):
            # Wrt("credType=%s<br>"%credType)
            credMapOut[credType] = dict()
            credNams = credMap[credType]
            for credName in sorted(credNams):
                cred = credNams[credName]
                # Wrt("cred=%s<br>"%str(cred))

                try:
                    # If the "_del" variable is ticked, do not copy the credentials.
                    cgiArguments[cred[3]]
                    wasChanged = True
                    continue
                except:
                    pass

                try:
                    # If the "_upd" variable is ticked, copy the credentials with a new password.
                    updPassword = cgiArguments[cred[2]].value
                    if updPassword != cred[1]:
                        wasChanged = True
                        Wrt("Name=%s: Replace %s by %s<br>"%(cred[0],cred[1],updPassword))
                        cred[1] = updPassword
                except:
                    pass

                credMapOut[credType][credName] = cred
                # Wrt("Added cred=%s<br>"%str(cred))

    except KeyError:
        Wrt("No upd nor del<br>")
        credMapOut = credMap
        pass

    if wasChanged:
        # Change the file only if something really changed.
        lib_credentials.UpdatesCredentials(credMapOut)
    return credMapOut


def Main():
    formAction = os.environ['SCRIPT_NAME']

    cgiArguments = cgi.FieldStorage()



    lib_util.HttpHeaderClassic(sys.stdout, "text/html")

    Wrt("""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head><title>Credentials</title></head>
    """)

    credFilename = os.path.normpath(lib_credentials.CredFilNam())

    Wrt("""
    <body>Have the same "SURVOL" header<br><br>Edit Survol credentials in %s<br><br>
    """ % credFilename)

    Wrt("Arg=%s<br><br>"%str(cgiArguments))

    InsertedCredMap(cgiArguments)

    credMap = UpdatedCredMap(cgiArguments)

    if credMap:
        FormUpdateCredentials(formAction,credMap)

    credTypesWellKnown = [
        "Login",
        "WMI",
        "Oracle",
        "WBEM",
        "RabbitMQ",
        "Azure",
        "ODBC",
    ]

    FormInsertCredentials(formAction, credTypesWellKnown)





    Wrt("""
    <br><a href="edit_configuration.py">Configuration</a>
    <br><a href="index.htm">Return to Survol</a>
    """)

    Wrt("""
    </body></html>""")

if __name__ == '__main__':
	Main()
