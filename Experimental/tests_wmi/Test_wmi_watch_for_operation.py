from __future__ import print_function

# http://timgolden.me.uk/python/wmi/wmi.html
import sys
import wmi

# Set up an event tracker on a WMI event. This function returns an wmi_watcher which can be called to get the next event:
cwmi = wmi.WMI()

watcher = cwmi.watch_for (
  notification_type="Operation",
  wmi_class="Win32_Process",
  delay_secs=2,
  Name='calc.exe'
)
process_id, result = cwmi.Win32_Process.Create(CommandLine="calc.exe")
print("Process created")

dict_processes = {}

def object_to_dict(wmi_object, class_name):
    dict_properties = {}
    cls_obj = getattr(cwmi, class_name)
    for prop_name in cls_obj.properties:
        prop_value = process_created.wmi_property(prop_name).value
        dict_properties[prop_name] = prop_value
    return dict_properties

while True:
    process_created = watcher()
    print("process_created.event_type=", process_created.event_type)
    new_values = object_to_dict(process_created, "Win32_Process")
    process_id = new_values["Handle"]

    def handle_creation():
        global dict_processes
        dict_processes[ process_id ] = new_values
        for prop_name, prop_value in new_values.items():
            print("    %s = %s" % (prop_name, prop_value))
        print("Keys=", dict_processes.keys())

    if process_created.event_type == "creation":
        handle_creation()
    elif process_created.event_type == "deletion":
        try:
            del dict_processes[process_id]
        except KeyError:
            print("Do not remove already present process:", process_id)
    elif process_created.event_type == "modification":
        try:
            old_values = dict_processes[process_id]
            # The keys MUST be the same.
            for prop_name in old_values:
                if old_values[ prop_name ] != new_values[ prop_name ]:
                    print("    %s: %s => %s" % ( prop_name, old_values[ prop_name ], new_values[ prop_name ]))
                    old_values[prop_name] = new_values[prop_name]
        except KeyError:
            print("Do not update but insert absent process:", process_id)
            handle_creation()
    else:
        raise Exception("Invalid event type:", process_created.event_type)


# valid_notification_types = ("operation", "creation", "deletion", "modification")
# Not sure for "operation".
# "operation" might trigger on any change to an object of that class.