
# Mettre ca dans les credentials.
subscription="Visual Studio Professional"
subscription_id = "8eae3913-8532-42f4-a66a-c5da7acdedd7"

# https://portal.azure.com/#asset/Microsoft_Azure_Billing/Subscription/8eae3913-8532-42f4-a66a-c5da7acdedd7

# Portail classique:
# https://manage.windowsazure.com/@rchateauneuhotmail.onmicrosoft.com#Workspaces/VisualStudioExtension/account

# Upload the certificate:
# https://blogs.endjin.com/2015/02/generating-and-using-a-certificate-to-authorise-azure-automation/
# Interface classique seulement ...
# https://manage.windowsazure.com/@rchateauneuhotmail.onmicrosoft.com#Workspaces/AdminTasks/ListManagementCertificates

# Machines MyFirstVM ou SecondVM : Yam****.123

# C:\windows\system32>makecert -sky exchange -r -n "CN=AzureCertificate" -pe -a sha1 -len 2048 -ss My "AzureCertificate.cer"

# [2016-06-21 08:10.29]  /drives/c
# [rchateau.rchateau-HP] ls -l Windows/*/AzureCertificate.cer
# -rwxrwx---    1 Administ UsersGrp       780 Jun 21 07:24 Windows/SysWOW64/AzureCertificate.cer
# -rwxrwx---    1 Administ UsersGrp       780 Jun 21 07:24 Windows/System32/AzureCertificate.cer

# Pourquoi la commande ls voit des fichiers que DIR et Windows Explorer ne voient pas ?

# C:\windows\system32>dir AzureCertificate.cer
#  Volume in drive C is Windows
#  Volume Serial Number is B66B-A584
#
#  Directory of C:\windows\system32
#
# File Not Found
#
# C:\windows\system32>ls AzureCertificate.cer
# AzureCertificate.cer
#
# C:\windows\system32>ls -l AzureCertificate.cer
# -rwx------+ 1 ???????? None 780 2016-06-21 07:24 AzureCertificate.cer
#
# C:\windows\system32>ls Azu*
# AzureCertificate.cer

# https://azure.microsoft.com/en-us/documentation/articles/cloud-services-python-how-to-use-service-management/
#
# The certificate is visible with the program certmgr, folder "Personal/Certificates"
#
from azure import *
from azure.servicemanagement import *

# subscription_id = '<your_subscription_id>'

# It is always there that errors are detected:
#  File "AzureTest.py", line 79, in <module>
#    result = sms.list_locations()
#  File "C:\Python27\lib\site-packages\azure\servicemanagement\servicemanagementservice.py", line 1128, in list_locations
#    Locations)

# Copy
#[2016-06-22 02:34.43]  /drives/c/windows/system32
#[rchateau.rchateau-HP] ? ls -l AzureCertificate.cer /drives/c/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/Tests/AzureCopy.cer
#-rwxrwx---    1 rchateau UsersGrp       780 Jun 22 02:34 /drives/c/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle/Tests/AzureCopy.cer
#-rwxrwx---    1 Administ UsersGrp       780 Jun 21 07:24 AzureCertificate.cer

#Traceback (most recent call last):
#    _WinHttpRequest._SetClientCertificate(self, _certificate)
#  File "_ctypes/callproc.c", line 945, in GetResult
#WindowsError: [Error -2147024809] The parameter is incorrect
#certificate_path = r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Tests\Toto.cer'

#Traceback (most recent call last):
#    raise SSLError(e, request=request)
#requests.exceptions.SSLError: [SSL] PEM lib (_ssl.c:2580)
#certificate_path = r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Tests\AzureCopy.cer'


#azure.common.AzureHttpError: Forbidden
#<Error xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
# <Code>ForbiddenError</Code><Message>The server failed to authenticate the request.
# Verify that the certificate is valid and is associated with this subscription.</Message></Error>
#certificate_path = 'CURRENT_USER\\my\\AzureCertificate'

#  File "_ctypes/callproc.c", line 945, in GetResult
#WindowsError: [Error -2147012852] Windows Error 0x80072F0C
#certificate_path = 'c:/Windows/System32/AzureCertificate.cer'

#  File "_ctypes/callproc.c", line 945, in GetResult
#WindowsError: [Error -2147024809] The parameter is incorrect
#certificate_path = 'Personal\\Certificates\\AzureCertificate'

#azure.common.AzureHttpError: Forbidden
#<Error xmlns="http://schemas.microsoft.com/windowsazure" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
# <Code>ForbiddenError</Code><Message>The server failed to authenticate the request.
# Verify that the certificate is valid and is associated with this subscription.</Message></Error>
certificate_path = 'AzureCertificate'

#### YES !!!!!!!!
sms = ServiceManagementService(subscription_id, certificate_path)

result = sms.list_locations()
for loca in result:
	print(loca.name)