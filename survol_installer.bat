@REM This is a simple demo installer for Survol..

@echo off
set "$py=0"
echo import sys; print('{0[0]}.{0[1]}'.format(sys.version_info^)^) >#.py
for /f "delims=" %%a in ('python #.py ^| findstr "2"') do set "$py=2"
for /f "delims=" %%a in ('python #.py ^| findstr "3"') do set "$py=3"
del #.py

goto:%$py%

echo python is not installed or python's path Path is not in the %%$path%% env. var
exit/b

:2
@python -m virtualenv %TMP%\survol-env
@goto:common_python_install

:3
@python -m venv %TMP%\survol-env
@goto:common_python_install

:common_python_install
%TMP%\survol-env\Scripts\pip --version
@REM Optional dependencies.
%TMP%\survol-env\Scripts\pip install pefile wmi pywin32 supervisor-win configparser
%TMP%\survol-env\Scripts\pip install survol

@REM Add a Python installer.

@REM The CGI server needs to point to the sources because they are executed as CGI scripts.
@REM This minimal implementation makes debugging much simpler.
@REM The WSGI server, on the other hand, imports survol subpackages.
@setlocal
@pushd %TMP%\survol-env\Lib\site-packages
%TMP%\survol-env\Scripts\python -c "import survol;print('v=',survol.__version__);import survol.scripts.cgiserver;print('f=',survol.scripts.cgiserver.__file__)"

@echo "Stop with Control-C"
%TMP%\survol-env\Scripts\python %TMP%\survol-env\Lib\site-packages\survol\scripts\cgiserver.py -b webbrowser
@popd
@endlocal

exit /b
