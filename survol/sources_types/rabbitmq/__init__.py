"""
RabbitMQ concepts
"""

def Graphic_shape():
	return "none"

def Graphic_colorfill():
	return "#FFCC66"

def Graphic_colorbg():
	return "#FFCC66"

def Graphic_border():
	return 2

def Graphic_is_rounded():
	return True

# managementUrl = rabbitmq.ManagementUrlPrefix(configNam)
# managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"users",namUser)
# managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"vhosts",namVHost)
# managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"exchanges",namVHost,namExchange)
# managementUrl = rabbitmq.ManagementUrlPrefix(configNam,"queues",namVHost,namQ)
# managementUrl = "http://" + configNam + "/#/queues/" + "%2F" + "/" + namQueue
# managementUrl = "http://" + configNam + "/#/vhosts/" + "%2F"
# managementUrl = "http://" + configNam + "/#/users/" + namUser
# managementUrl = "http://" + configNam + "/#/users/" + namUser
def ManagementUrlPrefix(configNam,key="vhosts",nameKey1="",nameKey2=""):
	prePrefix = "http://" + configNam + "/#/"
	if not key:
		return prePrefix

	if key == "users":
		return prePrefix + "users/" + nameKey1

	# It is a virtual host name.
	if nameKey1 == "/":
		effectiveVHost = "%2F"
	else:
		effectiveVHost = nameKey1
	effectiveVHost = effectiveVHost.lower() # RFC4343

	vhostPrefix = prePrefix + key + "/" + effectiveVHost

	if key in ["vhosts","connections"]:
		return vhostPrefix

	return vhostPrefix + "/" + nameKey2
