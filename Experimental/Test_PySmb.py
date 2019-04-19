import smb
from smb import SMBConnection

def smbwalk(conn, shareddevice, top = '/'):
    dirs , nondirs = [], []

    if not isinstance(conn, SMBConnection):
        raise TypeError("SMBConnection required")


    names = conn.listPath(shareddevice, top)

    for name in names:
        if name.isDirectory:
            if name.filename not in ['.', '..']:
                dirs.append(name.filename)
        else:
            nondirs.append(name.filename)

    yield top, dirs, nondirs

    for name in dirs:
        new_path = os.path.join(top, name)
        for x in smbwalk(conn, shareddevice, new_path):
            yield x


# //londata002/westdev/westdocs/testdata

conn = smb.SMBConnection.SMBConnection(username="", password="", my_name="", remote_name="", domain='')
# conn = SMBConnection(*con_str, domain='workgroup')
assert conn.connect('10.10.10.10')
ans = smbwalk(conn, 'SHARE_FOLDER',top= '/')