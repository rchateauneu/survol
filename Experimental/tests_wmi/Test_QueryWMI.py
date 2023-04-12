# This tests the execution of queries:
# The idea is to transform SPARQL into WQL which can be run on WMI or WBEM.

# Associators Of {Win32_NetworkAdapter.DeviceId=1}

import wmi

# This is a set of queries which can be executed in a reasonable time
# and are sufficiently complicated to be use as a source of inspiration
# for translation from SPARQL.

# https://www.codeproject.com/Articles/46390/WMI-Query-Language-by-Example
# https://docs.microsoft.com/en-us/windows/desktop/wmisdk/having-clause
lstQueries = [
    'Associators Of {Win32_NetworkAdapter.DeviceId=1}',
    'Select * From Win32_SerialPort',
    'Associators Of {Win32_NetworkAdapter.DeviceId=1} Where ResultClass = Win32_NetworkAdapterConfiguration',
    'Associators Of {Win32_NetworkAdapter.DeviceId=1} Where AssocClass = Win32_NetworkAdapterSetting',
    'References Of {Win32_NetworkAdapter.DeviceId=1}',
    # 'Select * From __InstanceCreationEvent Within 5 Where TargetInstance Isa "Win32_Process"',
    # 'Select * From __InstanceCreationEvent Within 5 Where TargetInstance Isa "Win32_Process" And TargetInstance.Name = "Notepad.exe"',
    # 'Select * From Meta_Class',
    'Select * From Meta_Class Where __Class = "Win32_LogicalDisk" ',
    'Select * From Meta_Class Where __Superclass Is Null and __Class Like "__%"',
    'Select * From Meta_Class Where __Superclass = "Win32_CurrentTime"',
    'Select * From Meta_Class Where __Dynasty = "Cim_Setting"',
    'Select * From Meta_Class Where __Class Like "Win32_Curr%"',
    'Select * From Meta_Class Where __This Isa "__Event" and __Class Like "Msft_WmiProvider_Op%"',
    'Select DisplayName,PathName From Win32_Service Where PathName like "C:\\WINDOWS\\system32\\w%.exe" ',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE AssocClass = Win32_SystemDevices',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE ClassDefsOnly',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE RequiredAssocQualifier = Association',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE RequiredQualifier = Locale',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE ResultClass = Cim_Directory',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE ResultRole = GroupComponent',
    'ASSOCIATORS OF {Win32_LogicalDisk.DeviceID="C:"} WHERE Role = GroupComponent',
    'Associators of {win32_LogicalDisk="C:"} where resultClass = Win32_Directory  requiredQualifier = Dynamic',
    #'REFERENCES OF {Adapter="AHA-294X"}',
    #'REFERENCES OF {Adapter="AHA-294X"} WHERE ClassDefsOnly',
    #'REFERENCES OF {Adapter="AHA-294X"} WHERE RequiredQualifier = AdapterTag',
    #'REFERENCES OF {Adapter="AHA-294X"} WHERE ResultClass = AdapterDriver',
    #'REFERENCES OF {Adapter="AHA-294X"} WHERE Role = parent',
    'REFERENCES OF {Win32_NetworkAdapter.DeviceID="0"} WHERE resultclass = Win32_NetworkAdapterSetting requiredQualifier = Dynamic',
    #'SELECT * FROM __InstanceModificationEvent WITHIN 2  WHERE TargetInstance ISA "Win32_LogicalDisk"',
]

c = wmi.WMI()
for qry in lstQueries:
    print("===========>",qry)
    try:
        for item in c.query(qry):
            print(item)
    except Exception as exc:
        print("Broken:",exc)
