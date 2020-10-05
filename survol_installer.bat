1>2# : ^
'''
@REM TODO: Create an installer in wxwidget for Apache, IIS etc.

@REM @echo off
set "$py=0"
echo import sys; print('{0[0]}.{0[1]}'.format(sys.version_info^)^) >#.py
for /f "delims=" %%a in ('python #.py ^| findstr "2"') do set "$py=2"
for /f "delims=" %%a in ('python #.py ^| findstr "3"') do set "$py=3"
del #.py

echo 
goto:%$py%

echo python is not installed or python's path Path is not in the %%$path%% env. var
exit/b

:2
echo Running with Python 2
@REM py -2.7 -m virtualenv %TMP%\survol-env
python -m virtualenv %TMP%\survol-env
goto:common_python_install

:3
echo Running with Python 3
@REM py -3.6 -m venv %TMP%\survol-env
python -m venv %TMP%\survol-env
goto:common_python_install

:common_python_install
%TMP%\survol-env\Scripts\pip --version
@REM Optional dependencies.
%TMP%\survol-env\Scripts\pip install pefile wmi pywin32 supervisor-win configparser
%TMP%\survol-env\Scripts\pip install survol

REM installer python.

%TMP%\survol-env\Scripts\python -c "import survol;print('v=',survol.__version__);import survol.scripts.cgiserver;print('f=',survol.scripts.cgiserver.__file__)"

pushd %TMP%\survol-env\Lib\site-packages
%TMP%\survol-env\Scripts\python %TMP%\survol-env\Lib\site-packages\survol\scripts\cgiserver.py -b webbrowser
popd

exit /b
