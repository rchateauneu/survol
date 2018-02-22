@REM "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
@REM "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe"

@REM set PATH=%PATH%;C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext

@REM set _NT_DEBUGGER_EXTENSION_PATH=C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext

popd "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
@REM popd "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86"
cdb.exe -G -r 0 -logo output.log -cf C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\Experimental\RetroBatch\retrobatch_cdb.ini python
pushd


@REM "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\winext\logexts.dll"
@REM
@REM
@REM
@REM
@REM
@REM
@REM
@REM
@REM
@REM
@REM

