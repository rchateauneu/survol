import pythoncom
import wmi
c = wmi.WMI (privileges=["Security"])

# wmi.x_access_denied:
# <x_wmi: Unexpected COM Error (-2147352567, 'Exception occurred.',
# (0, u'SWbemServicesEx', u'Access denied ', None, 0, -2147217405), None)>
watcher1 = c.watch_for (
  notification_type="Creation",
  wmi_class="Win32_NTLogEvent",
  Type="error"
)

watcher2 = c.watch_for (
  notification_type="Creation",
  wmi_class="Win32_NTLogEvent",
  Type="warning"
)

while 1:
  try:
    error_log = watcher1 (500)
  except wmi.x_wmi_timed_out:
    pythoncom.PumpWaitingMessages ()
  else:
    print error_log

  try:
    warning_log = watcher2 (500)
  except wmi.x_wmi_timed_out:
    pythoncom.PumpWaitingMessages ()
  else:
    print(warning_log)