# https://azure.microsoft.com/fr-fr/documentation/articles/cloud-services-python-how-to-use-service-management/

# Affichage de la liste des emplacements disponibles

# Pour afficher la liste des emplacements disponibles pour les services d'hébergement, utilisez la méthode list_locations :

from azure import *
from azure.servicemanagement import *

sms = ServiceManagementService(subscription_id, certificate_path)

result = sms.list_locations()
for location in result:
    print(location.name)
