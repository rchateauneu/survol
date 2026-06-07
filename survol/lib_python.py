import logging

def PipGetInstalledDistributions():
    try:
        import pip
        return pip.get_installed_distributions()
    except Exception as exc:
        logging.warning("PipGetInstalledDistributions (1) caught: %s", exc)
        pass

    try:
        import pip.utils
        return pip.utils.get_installed_distributions()
    except Exception as exc:
        logging.warning("PipGetInstalledDistributions (2) caught: %s", exc)
        pass

    try:
        # Not supported anymore in pip10 :
        # https://stackoverflow.com/questions/49923671/are-there-any-function-replacement-for-pip-get-installed-distributions-in-pip
        from pip._internal.utils.misc import get_installed_distributions
        return get_installed_distributions()
    except Exception as exc:
        logging.warning("PipGetInstalledDistributions (3) caught: %s", exc)
        pass

    try:
        import pkg_resources
        lst = list(pkg_resources.working_set)
        return lst
    except Exception as exc:
        logging.warning("PipGetInstalledDistributions (4) caught: %s", exc)
        pass

    logging.error("PipGetInstalledDistributions cannot get list of installed packages.")
    return None

