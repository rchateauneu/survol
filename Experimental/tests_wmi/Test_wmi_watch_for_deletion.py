import wmi
cwmi = wmi.WMI ()

# Edits the same file.
process_id, result = cwmi.Win32_Process.Create (CommandLine="notepad.exe " + __file__)
watcher = cwmi.watch_for (
    notification_type="Deletion",
    wmi_class="Win32_Process",
    delay_secs=1,
    ProcessId=process_id
)

while 1:
    process_deleted = watcher()
    # This works:
    print(process_deleted)
    print("Dir:", dir(process_deleted))
    print("Keys:", process_deleted.keys)
    print("Path:", process_deleted.path)
    print("properties:", process_deleted.properties)
    print("wmi_property:", process_deleted.wmi_property())
    print(process_deleted.Caption)
    print(dir(process_deleted))

