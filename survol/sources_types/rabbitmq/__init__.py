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
def ManagementUrlPrefix(config_nam, key="vhosts", name_key1="", name_key2=""):
    pre_prefix = "http://" + config_nam + "/#/"
    if not key:
        return pre_prefix

    if key == "users":
        return pre_prefix + "users/" + name_key1

    # It is a virtual host name.
    if name_key1 == "/":
        effective_v_host = "%2F"
    else:
        effective_v_host = name_key1
    effective_v_host = effective_v_host.lower() # RFC4343

    vhost_prefix = pre_prefix + key + "/" + effective_v_host

    if key in ["vhosts", "connections"]:
        return vhost_prefix

    return vhost_prefix + "/" + name_key2
