#!/usr/bin/env python

from __future__ import print_function

__author__ = "Remi Chateauneu"
__copyright__ = "Copyright 2020-2021, Primhill Computers"
__license__ = "GPL"

import os
import sys
import ast
import importlib

is_py2 = sys.version_info < (3,)

# pip install ..\dist\survol-1.0.dev0.zip --upgrade --install-option="--port 12345"

# TODO: Have a look to setuptools.setup
from distutils import log
from distutils.core import setup
from setuptools import find_packages

from setuptools.command.install import install
from setuptools.command.install_lib import install_lib
from setuptools.command.build_ext import build_ext
from distutils.command.clean import clean

# See https://gist.github.com/ctokheim/6c34dc1d672afca0676a for more details.
try:
    from Cython.Build import cythonize
except ImportError:
    cythonize = None

# If cython is present, it is used by default.
if cythonize:
    if '--without-cython' in sys.argv:
        USE_CYTHON = False
        sys.argv.remove('--without-cython')
    elif '--no-cython' in sys.argv:
        USE_CYTHON = False
        sys.argv.remove('--no-cython')
    else:
        USE_CYTHON = True
else:
    USE_CYTHON = False

if 'clean' in sys.argv:
    # Maybe Cython cannot work for some reason, and it would prevent cleaning up.
    USE_CYTHON = False

if is_py2:
    from future_builtins import filter

language_level = "2" if is_py2 else "3"


# https://stackoverflow.com/questions/677577/distutils-how-to-pass-a-user-defined-parameter-to-setup-py
#
# pip install -v displays methods calls and their outputs.
#
# The following methods are called, see -v option:
#    running install
#    Running initialize_options.


class InstallCommand(install):
    # The html files can be copied at any place.
    # For example at ~/public_html on Unix, i.e. "Users Dir feature of Apache".
    # TODO: These options are not used yet.
    user_options = install.user_options + [
        ('port=', 'p', 'CGI server port number'),  # Not used at the moment.
        ('www=', 'w', 'Web UI destination directory'),  # Not used at the moment.
    ]

    def initialize_options(self):
        print("Running initialize_options")
        install.initialize_options(self)
        self.port = 24680  # TODO: This is not used yet.

        # By default, cgiserver will pick its files from the Python installation directory,
        # and this is acceptable because they are part of the same package.

        # http://setuptools.readthedocs.io/en/latest/setuptools.html#automatic-script-creation
        # For the default destination of HTML pages, see also "pkg_resources" and the likes:
        # "The distutils normally install general "data files" to a platform-specific location (e.g. /usr/share)"
        # So it is possible to install the HTML pages in a normal directory, and also in a location,
        # standard for Python, where Python modules can retrieve them. and also the Python server.
        self.www = None

    def finalize_options(self):
        print('The port number for install is:%s' % self.port)
        install.finalize_options(self)

    def run(self):
        # This must be given to a parameter file for cgiserver.
        my_port = self.port

        # The HTML, css and js files must be copied at this place.
        # This avoids to have a HTTP server such as Apache or IIS,
        # pick its files from the Python installation dir.
        my_www = self.www

        # Also, the css and js files must be copied into the Python directory.

        print("Custom installation. Port:%s Dest dir=%s" % (my_port, my_www))
        if my_www:
            print("About to copy %s" % my_www)
        install.run(self)  # OR: install.do_egg_install(self)


def _script_to_cgi_executable(one_path):
    """
    This rewrites a Python script, making it executable by setting the Linux flag,
    and also fixes the line terminator to Linxu standard, if necessary.

    TODO: Consider the command: build_scripts: "build" scripts (copy and fixup #! line)
    """
    with open(one_path, 'rb') as input_stream:
        # Binary read so the line terminator is intact.
        file_content = input_stream.readlines()

    if len(file_content) == 0:
        log.info("InstallLibCommand empty file=%s" % one_path)
        return

    # By convention, all Survol CGI scripts start with this header line.
    # There must not be any CR character after this shebang line.
    if file_content[0].startswith(b"#!/usr/bin/env python"):
        log.info("Script file=%s l=%d" % (one_path, len(file_content)))
        try:
            # Maybe this file is a script. If so, remove "CRLF" at the end.
            lines_number = 0
            with open(one_path, 'wb') as output_stream:
                for one_line in file_content:
                    if one_line.endswith((b'\r\n', b'\n\r')):
                        output_stream.write(b"%s\n" % one_line[:-2])
                    else:
                        output_stream.write(one_line)
                    lines_number += 1

            log.info("Script written=%d" % lines_number)
            # Set executable flag for Linux CGI scripts.
            os.chmod(one_path, 0o744)
        except Exception as exc:
            log.error("Script err=%s" % exc)

is_linux_or_darwin = sys.platform.startswith("lin") or sys.platform == "darwin"

class InstallLibCommand(install_lib):
    """
    On Linux and Darwin, this converts Python files to proper Unix format, and sets the executable flag.
    This is needed because setup.py does not keep the executable flag information.
    Also, files stored in Github have Windows lines terminators.
    So, to be sure, this strips these line terminators which are invalid in Linux shell scripts.
    """

    def copy_tree(
            self, infile, outfile,
            preserve_mode=1, preserve_times=1, preserve_symlinks=0, level=1
    ):
        """This is called on Linux and Darwin, from the top-level infile='build\\lib' """
        if is_linux_or_darwin:
            library_top = os.path.join(infile, "survol")
            for library_root, library_dirs, library_files in os.walk(library_top):
                for one_file in library_files:
                    if one_file.endswith(".py"):
                        one_path = os.path.join(library_root, one_file)
                        self._script_to_cgi_executable(one_path)

        return install_lib.copy_tree(self, infile, outfile,
                                     preserve_mode, preserve_times, preserve_symlinks, level)


def _cythonizable_source_files():
    """
    This returns the list of absolute paths of files to be cythonized.

    Only a subset of files are compiled.
    """
    survol_base_dir = os.path.join(os.path.dirname(__file__), "survol")
    src_files = []

    basenames_list = [
        "scripts/linux_api_definitions.py",
        "scripts/win32_api_definitions.py",
        # "cim_objects_definitions",
        # Import problem with Python 3
        ## "naming_conventions",

        # Unexplained bug yet (In summarization of function calls).
        # "dockit",
        "scripts/dockit_aggregate_clusterize.py",
    ]

    for root, dir, top_level_files in os.walk(survol_base_dir):
        break

    not_compiled_files = set([
        # https://stackoverflow.com/questions/19630634/python-file-is-not-defined
        "lib_util.py",
        # survol\lib_client.py:875:63: Compiler crash in AnalyseExpressionsTransform
        "lib_client.py",
        # LINK : error LNK2001: unresolved external symbol init__init__
        "__init__.py",
        # AttributeError: 'module' object has no attribute 'gUriGen'
        "lib_common.py",
    ])
    for one_file in top_level_files:
        if one_file.endswith(".py") and one_file not in not_compiled_files:
            basenames_list.append(one_file)

    for one_filename in basenames_list:
        one_path_name = os.path.join(survol_base_dir, one_filename)
        src_files.append(one_path_name)
    return src_files


class BuildExtCommand(build_ext):
    """
    A custom command to build Cython extensions.

    This is needed otherwise setup does not build or rebuild C files from Python source files.
    FIXME: Not sure why the presence of this custom command which does not do much, fix the build issue.

    Usage example: python setup.py build_ext --inplace
    It ignores build-lib and put compiled extensions into the source directory alongside the pure Python modules.
    These libraries are prioritized before *.py files by Python, and loaded instead.
    """

    description = 'Build Cython extensions'

    def initialize_options(self):
        print("build_ext.initialize_options")
        build_ext.initialize_options(self)

    def finalize_options(self):
        """Post-process options."""
        print("build_ext.finalize_options")
        build_ext.finalize_options(self)

    def run(self):
        """Run command."""
        print("build_ext.run")
        build_ext.run(self)


class CleanCommand(clean):
    """
    Clean build including iniplace built extensions.
    """

    description = 'Clean build including in-place built extensions.'

    def _cleanup_libs(self):
        def remove_lib_file(lib_path):
            try:
                os.remove(lib_path)
                print("removed cythonized file:", lib_path)
            except:
                print("Cannot remove:", lib_path)

        src_files = _cythonizable_source_files()
        for one_file in src_files:
            assert one_file.endswith(".py")
            file_without_extension = os.path.splitext(one_file)[0]
            if sys.platform.startswith("lin") or sys.platform == "darwin":
                lib_path = file_without_extension + ".so"
                remove_lib_file(lib_path)
            else:
                # for example: ['.cp36-win_amd64.pyd', '.pyd']
                for one_suffix in importlib.machinery.EXTENSION_SUFFIXES:
                    # The file name might be something like: "collection.cp36-win_amd64.pyd"
                    lib_path = file_without_extension + one_suffix
                    remove_lib_file(lib_path)

    def run(self):
        """Run command."""
        print("Removing in-place built libs")
        self._cleanup_libs()
        clean.run(self)


# Some explanations: The Python scripts in survol/sources_types (Plus some of them
# in survol/ like survol/entity.py etc...) are CGI scripts.
# Therefore, they can easily be run, debugged and tested in isolation, without a HTTP server.
# These scripts can also be imported: This is how the WSGI server works.
# Some CGI scripts could easily be rewritten in another language for performance.

def package_files(directory):
    """The current directory is where setup.py is."""
    paths = []
    for path, directories, filenames in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths


# HTML and Javascript files for the D3 interface.
extra_files = package_files('survol/www')

# This file is needed for the events generators processes, started by the package supervisor.
extra_files += ['survol/scripts/supervisord.conf']

# The created zip archive contains directories: docs, survol and tests.

# This extracts the version number from the file "survol/__init__.py"
with open(os.path.join('survol', '__init__.py')) as f:
    __version__ = ast.parse(next(filter(lambda line: line.startswith('__version__'), f))).body[0].value.s

with open('README.txt') as readme_file:
    README = readme_file.read()

# FIXME: Cleanup the doc strings, for example survol.__doc__ = '\nSurvol library\n' ...

# These packages are mandatory.
required_packages = ['psutil', 'rdflib']
if is_py2:
    required_packages.append("configparser")
# Other very useful packages: "wmi", "pywbem", "rdflib-sqlalchemy".

setup_options = dict(
    name='survol',
    version=__version__,
    description='Exploring legacy IT systems',
    long_description=README,
    author='Primhill Computers',
    author_email='contact@primhillcomputers.com',
    url='http://www.primhillcomputers.com/survol.html',
    packages=find_packages(),
    package_dir={"survol": "survol"},
    # This is apparently not recursive.
    package_data={'survol': extra_files},
    entry_points={'console_scripts': [
        'survolcgi = survol.scripts.cgiserver:cgiserver_entry_point',
        'survolwsgi = survol.scripts.wsgiserver:wsgiserver_entry_point',
        'dockit = survol.scripts.wsgiserver:dockit_entry_point',
    ]},
    install_requires=required_packages,
    cmdclass={
        'install': InstallCommand,
        'install_lib': InstallLibCommand,
        'clean': CleanCommand,
        'build_ext': BuildExtCommand,
    },
    scripts=['survol/scripts/cgiserver.py', 'survol/scripts/wsgiserver.py', 'survol/scripts/dockit.py'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Education',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Python Software Foundation License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: JavaScript',
        'Topic :: Software Development :: Bug Tracking',
        'Topic :: Education',
        'Topic :: Software Development :: Documentation',
        'Topic :: System :: Systems Administration',
        'Topic :: Documentation'
    ]
)

if USE_CYTHON:
    src_files = _cythonizable_source_files()
    cython_ext_modules = cythonize(
        src_files,
        build_dir="build_cythonize",
        # nthreads = 3,
        annotate=True,
        compiler_directives={'language_level': language_level})

    # With "force", the C code is regenerated each time.
    # Otherwise, setup does not detect an input Python file change.
    # Maybe this can be forced with: python setup.py build_ext --force
    cython_options = dict(
        ext_modules=cython_ext_modules,

        # script_args=['build'],
        options={
            #'build': {'build_lib': 'build_build_ext', 'force': 1},
            'build': {'build_lib': 'build_build_ext'},
        })
    setup_options.update(cython_options)


setup(**setup_options)

################################################################################

# APPENDIX: Some tips about the installation of Survol under Apache.
#
# Two installations types are possible:
# (1) With the CGI scripts cgiserver, which just need to be accessible,
# and imports survol Python modules, installed by sdist.
# (2) Or if Apache runs the sources files from the development directory or from the installed packages.
# This is what is demonstrated here.

# Alias /Survol "C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle"
# <Directory "C:/Users/rchateau/Developpement/ReverseEngineeringApps/PythonStyle" >
#    Options Indexes FollowSymLinks Includes ExecCGI
#    Allow from all
#    AddHandler cgi-script .py
#	# http://stackoverflow.com/questions/2036577/how-do-i-ignore-the-perl-shebang-on-windows-with-apache-2
#	ScriptInterpreterSource Registry-Strict
#	# SetEnv PYTHONPATH C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\revlib
# </Directory>

################################################################################

## Appendix'appendix: How to install Yawn, which is an HTML navigator into OpenLmi (Pegasus) objects and classes.
## apache's configuration file for yawn using wsgi
## We could add this content in yawn.conf and incldue the content.
# WSGIScriptAlias /yawn "C:/Users/rchateau/Developpement/ReverseEngineeringApps/pywbem_all/pywbem_sourceforge/yawn2/trunk/mod_wsgi/yawn_wsgi.py"

## For development convenience, no need to install anything because we point to the development files.
# <Directory "C:/Users/rchateau/Developpement/ReverseEngineeringApps/pywbem_all/pywbem_sourceforge/yawn2/trunk/mod_wsgi>
#    # Options Indexes FollowSymLinks Includes ExecCGI
#    Options ExecCGI
#    # Allow from all
#    WSGIPassAuthorization On
#    # AddHandler cgi-script .py
#	# http://stackoverflow.com/questions/2036577/how-do-i-ignore-the-perl-shebang-on-windows-with-apache-2
#	# ScriptInterpreterSource Registry-Strict
#	SetEnv PYTHONPATH C:\Users\rchateau\Developpement\ReverseEngineeringApps\pywbem_all\pywbem_sourceforge\yawn2\trunk\mod_wsgi\pywbem_yawn
# </Directory>

################################################################################

