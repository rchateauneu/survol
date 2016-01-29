# https://sjohannes.wordpress.com/2012/03/23/win32-python-getting-all-window-titles/

import sys
import ctypes

# from __future__ import unicode_literals

# http://sametmax.com/lencoding-en-python-une-bonne-fois-pour-toute/
import encodings
print( ''.join('- ' + e + '\n' for e in sorted(set(encodings.aliases.aliases.values()))) )

 
# EnumWindows = ctypes.windll.user32.EnumWindows
# GetWindowText = ctypes.windll.user32.GetWindowTextW
# GetWindowTextLength = ctypes.windll.user32.GetWindowTextLengthW
# IsWindowVisible = ctypes.windll.user32.IsWindowVisible
 
titles = []

def foreach_window(hwnd, lParam):
	if ctypes.windll.user32.IsWindowVisible(hwnd):
		length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
		buff = ctypes.create_unicode_buffer(length + 1)
		ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)

		# Not aavailable in Python
		# If the specified window is a control, the text of the control is obtained.
		# buffIntern = ctypes.create_unicode_buffer(1000)
		# ctypes.windll.user32.InternalGetWindowText( hwnd, buffIntern, 1000 )

		# Nothing interesting to display.
		if buff.value == "":
			return

		curr_proc_id = ctypes.c_long()
		ctypes.windll.user32.GetWindowThreadProcessId( hwnd, ctypes.byref(curr_proc_id))
		# print("curr_proc_id=%s" % str(curr_proc_id) )
		# print("curr_proc_id=%d" % int(curr_proc_id.value) )
		titles.append( [curr_proc_id.value, buff.value ] )
		#print("%s" % buffIntern.value )
		# print("A pid=%s %s : %s " % (curr_proc_id.value, buff.value, buffIntern.value) )
	return True

EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))

ctypes.windll.user32.EnumWindows(EnumWindowsProc(foreach_window), 0)

for lst in titles :
	try:
		print("B pid=%s %s" % (lst[0],lst[1]) )
	except UnicodeEncodeError:
		# http://stackoverflow.com/questions/14630288/unicodeencodeerror-charmap-codec-cant-encode-character-maps-to-undefined
		# =========== Unicode error: b'Thucydide \xe2\x80\x94 Wikip\xc3\xa9dia - Google Chrome'
		# print("=========== Unicode error: %s" % lst[1].encode('utf-8') )

		# UnicodeEncodeError: 'ascii' codec can't encode character '\u2014' in position 10: ordinal not in range(128)
		# print("=========== Unicode error: %s" % lst[1].encode('ascii') )

		print("=========== Unicode error: %s" % lst[1].encode('utf-8') )
		# ("=========== Unicode error: %s" % lst[1].encode('unicode') )
		print("=========== Unicode error: %s" % lst[1].encode(sys.stdout.encoding, errors='replace') ) 




