
subscription="Visual Studio Professional"
subscription_id = "8eae3913-8532-42f4-a66a-c5da7acdedd7"

# https://azure.microsoft.com/en-us/documentation/articles/cloud-services-python-how-to-use-service-management/

from azure import *
from azure.servicemanagement import *

# subscription_id = '<your_subscription_id>'
certificate_path = 'CURRENT_USER\\my\\AzureCertificate'

sms = ServiceManagementService(subscription_id, certificate_path)