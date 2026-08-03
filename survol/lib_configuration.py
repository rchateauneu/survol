import os
import json
import lib_util

def ConfigFilename():
    home_path = lib_util.get_home_directory()
    config_file_name = os.path.join(home_path, "SurvolConfig.json")
    return config_file_name


DEFAULT_CONFIG = {
    "cgi_server_port": "8000",
    "wsgi_server_port": "9000",
    "bookmark_url": "bookmarks.htm",
    "html_jinja2": False,
    "graphviz_wsl": False,
}


def LoadConfig():
    """Read SurvolConfig.json if it exists, otherwise use the defaults."""
    config = DEFAULT_CONFIG.copy()
    config_file_name = ConfigFilename()

    if os.path.exists(config_file_name):
        try:
            with open(config_file_name, "r", encoding="utf-8") as config_file:
                saved_config = json.load(config_file)
            if isinstance(saved_config, dict):
                for name in DEFAULT_CONFIG:
                    if name in saved_config:
                        config[name] = saved_config[name]
        except (OSError, ValueError, TypeError):
            # If the file cannot be read, keep the defaults.
            pass

    config["cgi_server_port"] = str(config["cgi_server_port"])
    config["wsgi_server_port"] = str(config["wsgi_server_port"])
    config["bookmark_url"] = str(config["bookmark_url"])
    config["html_jinja2"] = bool(config["html_jinja2"])
    config["graphviz_wsl"] = bool(config["graphviz_wsl"])
    return config


def SaveConfig(config):
    with open(ConfigFilename(), "w", encoding="utf-8") as config_file:
        json.dump(config, config_file, indent=4)
        config_file.write("\n")
