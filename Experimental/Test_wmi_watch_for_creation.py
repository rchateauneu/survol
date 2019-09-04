# http://timgolden.me.uk/python/wmi/wmi.html
import wmi

# Set up an event tracker on a WMI event. This function returns an wmi_watcher which can be called to get the next event:
c = wmi.WMI()

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
    watcher = c.watch_for (
      notification_type="Creation",
      wmi_class="Win32_Process",
      delay_secs=2,
      Name='calc.exe'
    )
    while 1:
        process_created = watcher ()
        # This works:
        print(process_created)
        #instance of Win32_Process
        #{
        #    Caption = "calc.exe";
        #    CommandLine = "\"C:\\windows\\system32\\calc.exe\" ";
        #    Name = "calc.exe";

        print(process_created.Caption)
        print(dir(process_created))


        # print(process_created.Caption)
        # File "C:\Python27\lib\site-packages\wmi.py", line 561, in __getattr__
        # return getattr (self.ole_object, attribute)
        # File "C:\Python27\lib\site-packages\win32com\client\__init__.py", line 465, in __getattr__
        # raise AttributeError("'%s' object has no attribute '%s'" % (repr(self), attr))
        # AttributeError: '<win32com.gen_py.Microsoft WMI Scripting V1.2 Library.ISWbemObjectEx instance at 0x40235144>' object has no attribute 'Caption'

