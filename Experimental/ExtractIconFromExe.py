# https://stackoverflow.com/questions/23263599/how-to-extract-128x128-icon-bitmap-data-from-exe-in-python
# Use wchar_t function version (FindResourceW rather than FindResourceA)
from __future__ import unicode_literals

# pywin32 imports
import win32con
import win32api
import win32file
import win32gui
import win32ui
import pywintypes

# ctypes configuring. pywin32 has no a lot of required functions
import ctypes
import ctypes.util

# memcpy used to copy data from resource storage to our buffer
libc = ctypes.CDLL(ctypes.util.find_library('c'))
libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
libc.memcpy.restype = ctypes.c_char_p

# patch FindResourceW, ctypes.windll.kernel32.SizeofResource
FindResourceW = ctypes.windll.kernel32.FindResourceW
FindResourceW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
FindResourceW.restype = ctypes.c_void_p
SizeofResource = ctypes.windll.kernel32.SizeofResource
SizeofResource.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
SizeofResource.restype = ctypes.c_size_t

# Using LoadLibrary (rather than CreateFile) is required otherwise
# LoadResource, FindResource and others will fail
PATH = "C:\\Program Files\\Internet Explorer\\iexplore.exe"
hlib = win32api.LoadLibraryEx(PATH, 0, 2)

# get icon groups, default is the first group
icon_groups = win32api.EnumResourceNames(hlib, win32con.RT_GROUP_ICON)
group_name = icon_groups[0]
print group_name
hRes = win32api.LoadResource(hlib, win32con.RT_GROUP_ICON, group_name)
mem_icon_dir = ctypes.windll.kernel32.LockResource(hRes)

# 32 bits color; 16 and 256 colors are too old
# iterate through the common sizes
icon_sizes = (16, 24, 32, 48, 96, 256)
for icon_size in icon_sizes:
    icon_name = ctypes.windll.user32.LookupIconIdFromDirectoryEx(mem_icon_dir, True, icon_size, icon_size, 0x00000000);
    hResInfo = FindResourceW(hlib, icon_name, win32con.RT_ICON)
    size = ctypes.windll.kernel32.SizeofResource(hlib, hResInfo)
    rec = win32api.LoadResource(hlib, win32con.RT_ICON, icon_name)
    mem_icon = ctypes.windll.kernel32.LockResource(rec)

    # And this is some differ (copy data to Python buffer)
    binary_data = (ctypes.c_ubyte * size)()
    libc.memcpy(binary_data, mem_icon, size)
    hIconRet = ctypes.windll.user32.CreateIconFromResourceEx(binary_data, size, True, 0x00030000, 0, 0, 0x00000000);
    info = win32gui.GetIconInfo(hIconRet)
    bminfo = win32gui.GetObject(info[4])

    # generate bitmap by drawing the icon
    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
    hbmp = win32ui.CreateBitmap()
    hbmp.CreateCompatibleBitmap(hdc, bminfo.bmWidth, bminfo.bmHeight)
    hcdc = hdc.CreateCompatibleDC()
    hcdc.SelectObject(hbmp)
    win32gui.DrawIconEx(hcdc.GetHandleOutput(), 0, 0, hIconRet, bminfo.bmWidth, bminfo.bmHeight, 0, 0, 0x0003)

	# Need temp directory or generate image on the fly, for inclusion into an HTML page.
	# Temp file visible from HTTP server.
    hbmp.SaveBitmapFile(hcdc, "icon-%03dx%03d-%05d-%03d.bmp" % (bminfo.bmWidth, bminfo.bmHeight, group_name, icon_name))
    win32gui.DestroyIcon(hIconRet)