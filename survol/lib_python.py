def PipGetInstalledDistributions():
    try:
        import pip
        return pip.get_installed_distributions()
    except:
        pass

    try:
        import pip.utils
        return pip.utils.get_installed_distributions()
    except:
        pass

    try:
		# Not supported anymore in pip10 :
		# https://stackoverflow.com/questions/49923671/are-there-any-function-replacement-for-pip-get-installed-distributions-in-pip
        from pip._internal.utils.misc import get_installed_distributions
        return get_installed_distributions()
    except:
        pass

    return None

