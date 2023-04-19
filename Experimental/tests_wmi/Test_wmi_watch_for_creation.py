# http://timgolden.me.uk/python/wmi/wmi.html
import sys
import wmi

# Set up an event tracker on a WMI event. This function returns an wmi_watcher which can be called to get the next event:
cwmi = wmi.WMI()

if False:
    # This does not work.
    # wmi_class = getattr (self, class_name)
    # TypeError: getattr(): attribute name must be string
    raw_wql = "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"
    watcher = c.watch_for(raw_wql=raw_wql)
    while 1:
        process_created = watcher()
        print(process_created.Name)
else:

    watcher = cwmi.watch_for (
      notification_type="Creation",
      wmi_class="Win32_Process",
      delay_secs=2,
      Name='calc.exe'
    )
    process_id, result = cwmi.Win32_Process.Create(CommandLine="calc.exe")
    print("Process created")

    while 1:
        process_created = watcher()

        print("PROPERTIES")
        class_name = "Win32_Process"
        cls_obj = getattr(cwmi, class_name)
        for prop_name in cls_obj.properties:
            prop_value = process_created.wmi_property(prop_name).value
            print(prop_name, prop_value)

        if False:
            # Tried to find a way to get the class name instead of assuming it is the same.

            # This works:
            print(process_created)
            # instance of Win32_Process
            # {
            #     Caption = "calc.exe";
            #     CommandLine = "calc.exe";
            #     CreationClassName = "Win32_Process";
            #     CreationDate = "20190907114425.161074+060";
            #     CSCreationClassName = "Win32_ComputerSystem";
            #     CSName = "RCHATEAU-HP";
            #     Description = "calc.exe";
            #     ExecutablePath = "C:\\windows\\system32\\calc.exe";
            #     Handle = "26836";
            #     HandleCount = 70;
            #     KernelModeTime = "468003";
            #     MaximumWorkingSetSize = 1380;
            #     MinimumWorkingSetSize = 200;
            #     Name = "calc.exe";
            #     OSCreationClassName = "Win32_OperatingSystem";
            #     OSName = "Microsoft Windows 7 Professional |C:\\windows|\\Device\\Harddisk0\\Partition2";
            #     OtherOperationCount = "314";
            #     OtherTransferCount = "936";
            #     PageFaults = 3139;
            #     PageFileUsage = 5252;
            #     ParentProcessId = 29652;
            #     PeakPageFileUsage = 5252;
            #     PeakVirtualSize = "86781952";
            #     PeakWorkingSetSize = 12200;
            #     Priority = 8;
            #     PrivatePageCount = "5378048";
            #     ProcessId = 26836;
            #     QuotaNonPagedPoolUsage = 17;
            #     QuotaPagedPoolUsage = 159;
            #     QuotaPeakNonPagedPoolUsage = 17;
            #     QuotaPeakPagedPoolUsage = 160;
            #     ReadOperationCount = "2";
            #     ReadTransferCount = "26642";
            #     SessionId = 1;
            #     ThreadCount = 3;
            #     UserModeTime = "0";
            #     VirtualSize = "86781952";
            #     WindowsVersion = "6.1.7601";
            #     WorkingSetSize = "12492800";
            #     WriteOperationCount = "0";
            #     WriteTransferCount = "0";
            # };

            # ('dir(process_created)=',
            #  ['__doc__', '__eq__', '__getattr__', '__hash__', '__init__', '__lt__', '__module__', '__repr__', '__setattr__',
            #   '__str__', '_associated_classes', '_cached_associated_classes', '_cached_methods', '_cached_properties',
            #   '_getAttributeNames', '_get_keys', '_instance_of', '_keys', '_methods', '_properties', 'associated_classes',
            #   'associators', 'derivation', 'event_type', 'event_type_re', 'id', 'keys', 'methods', 'ole_object', 'path',
            #   'previous', 'properties', 'property_map', 'put', 'qualifiers', 'references', 'set', 'timestamp',
            #   'wmi_property'])
            print("dir(process_created)=", dir(process_created))

            # <class wmi._wmi_event at 0x00000000026EBB28>
            print("process_created.__class__=", process_created.__class__)
            print("keys=", process_created.keys)

            # object has no attribute 'associated_classes'
            # print("associated_classes=",process_created.associated_classes)

            print("path()=", process_created.path())

            # This does not work as expected:
            # ('properties=', {'*': None, 'TargetInstance': None})
            print("properties=", process_created.properties)

            # object has no attribute 'name'
            # print("name=",process_created.name)
            print("set()=", process_created.set())
            print("property_map=", process_created.property_map)
            print("qualifiers=", process_created.qualifiers)
            print("properties=", process_created.properties)
            print("references=", process_created.references())

            print("qualifiers=", process_created.qualifiers)

            # See the implementation in https://github.com/cloudbase/wmi/blob/master/wmi.py
            # def wmi_property(self, property_name):
            #     return _wmi_property(self.ole_object.Properties_(property_name))
            #
            # ('dir(ole_object)=',
            #  ['AssociatorsAsync_', 'Associators_', 'CLSID', 'Clone_', 'CompareTo_', 'DeleteAsync_', 'Delete_',
            #   'ExecMethodAsync_', 'ExecMethod_', 'GetObjectText_', 'GetText_', 'InstancesAsync_', 'Instances_', 'PutAsync_',
            #   'Put_', 'ReferencesAsync_', 'References_', 'Refresh_', 'SetFromText_', 'SpawnDerivedClass_', 'SpawnInstance_',
            #   'SubclassesAsync_', 'Subclasses_', '_ApplyTypes_', '__doc__', '__eq__', '__getattr__', '__init__', '__iter__',
            #   '__module__', '__ne__', '__repr__', '__setattr__', '_get_good_object_', '_get_good_single_object_',
            #   '_oleobj_', '_prop_map_get_', '_prop_map_put_', 'coclass_clsid'])
            #
            print("ole_object=", process_created.ole_object)
            print("dir(ole_object)=", dir(process_created.ole_object))

            # dir() does not show all members and properties ...
            # ('dir(ole_object.Properties_)=',
            # ['Add', 'CLSID', 'Item', 'Remove', '_ApplyTypes_', '__call__', '__doc__', '__eq__', '__getattr__',
            # '__init__', '__int__', '__iter__', '__len__', '__module__', '__ne__', '__nonzero__', '__repr__',
            # '__setattr__', '__str__', '__unicode__', '_get_good_object_', '_get_good_single_object_',
            # '_oleobj_', '_prop_map_get_', '_prop_map_put_', 'coclass_clsid'])
            print("dir(ole_object.Properties_)=", dir(process_created.ole_object.Properties_))

            # ('ole_object.Properties_=', <win32com.gen_py.Microsoft WMI Scripting V1.2 Library.ISWbemPropertySet instance at 0x40608072>)
            print("ole_object.Properties_=", process_created.ole_object.Properties_)
            print("len(ole_object.Properties_)=", len(process_created.ole_object.Properties_))
            print("list(ole_object.Properties_)=", list(process_created.ole_object.Properties_))

            list_props = list(process_created.ole_object.Properties_)
            print("type(list(ole_object.Properties_))=", type(list_props))
            print("list(ole_object.Properties_)[0]=", list_props[0])
            # ('dir(list(ole_object.Properties_)[0])=',
            #  ['CLSID', '_ApplyTypes_', '__call__', '__doc__', '__eq__', '__getattr__', '__init__', '__int__', '__iter__',
            #   '__module__', '__ne__', '__repr__', '__setattr__', '__str__', '__unicode__', '_get_good_object_',
            #   '_get_good_single_object_', '_oleobj_', '_prop_map_get_', '_prop_map_put_', 'coclass_clsid'])
            print("dir(list(ole_object.Properties_)[0])=", dir(list_props[0]))

            # ('list(ole_object.Properties_)[0]=', 'calc.exe')
            print("list(ole_object.Properties_)[0]=", str(list_props[0]))

            # ('dir(wmi_property)=',
            #  ['__class__', '__delattr__', '__dict__', '__doc__', '__format__', '__getattr__', '__getattribute__',
            #   '__hash__', '__init__', '__module__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
            #   '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'name', 'property', 'qualifiers', 'set', 'type',
            #   'value'])
            print("wmi_property('Caption')=", process_created.wmi_property("Caption"))

            # ("wmi_property('Caption').value=", u'calc.exe')
            print("wmi_property('Caption').value=", process_created.wmi_property("Caption").value)

            print("dir(wmi_property('Caption'))=", dir(process_created.wmi_property("Caption")))

            sys.stdout.flush()

            # ['__doc__', '__eq__', '__getattr__', '__hash__', '__init__', '__lt__', '__module__', '__repr__',
            # '__setattr__', '__str__', '_associated_classes', '_cached_associated_classes', '_cached_methods',
            # '_cached_properties', '_getAttributeNames', '_get_keys', '_instance_of', '_keys', '_methods',
            # '_properties', 'associated_classes', 'associators', 'derivation', 'event_type', 'event_type_re',
            # 'id', 'keys', 'methods', 'ole_object', 'path', 'previous',
            # 'properties', 'property_map', 'put', 'qualifiers', 'references', 'set', 'timestamp', 'wmi_property']
            print(dir(process_created))

            # object has no attribute 'Caption'
            # print(process_created.Caption)


            # print(process_created.Caption)
            # File "C:\Python27\lib\site-packages\wmi.py", line 561, in __getattr__
            # return getattr (self.ole_object, attribute)
            # File "C:\Python27\lib\site-packages\win32com\client\__init__.py", line 465, in __getattr__
            # raise AttributeError("'%s' object has no attribute '%s'" % (repr(self), attr))
            # AttributeError: '<win32com.gen_py.Microsoft WMI Scripting V1.2 Library.ISWbemObjectEx instance at 0x40235144>' object has no attribute 'Caption'

            print(dir(process_created))
            print("_instance_of=",process_created._instance_of)
            print("id=",process_created.id)
            print(process_created.derivation())
            print("process_created.event_type=",process_created.event_type)
            print(process_created.event_type_re)
            print(process_created.__class__)
            print(dir(process_created.ole_object))
            print("process_created.ole_object.CLSID=",process_created.ole_object.CLSID)
            print("process_created.ole_object.coclass_clsid=",process_created.ole_object.coclass_clsid)
            print("process_created.ole_object.__class__=",process_created.ole_object.__class__)
            # ISWbemObjectEx
            print(process_created.ole_object.__class__.__name__)

# valid_notification_types = ("operation", "creation", "deletion", "modification")
# Not sure for "operation".
# "operation" might trigger on any change to an object of that class.