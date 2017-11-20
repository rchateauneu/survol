#!/usr/bin/python

"""
Unix domain sockets
"""

# The Python module psutil is not needed

# $ netstat -a --unix -p
# Active UNIX domain sockets (servers and established)
# Proto RefCnt Flags       Type       State         I-Node   PID/Program name     Path
# unix  2      [ ACC ]     STREAM     LISTENING     29819    1972/gnome-session   @/tmp/.ICE-unix/1972
# unix  2      [ ACC ]     STREAM     LISTENING     28085    1888/Xorg            @/tmp/.X11-unix/X0
# unix  2      [ ACC ]     STREAM     LISTENING     29463    1968/dbus-daemon     @/tmp/dbus-cpj6sQNfQb
# unix  2      [ ACC ]     STREAM     LISTENING     20787    -                    /run/user/42/pulse/native
# unix  2      [ ]         DGRAM                    27201    1784/systemd         /run/user/1000/systemd/notify
# unix  7      [ ]         DGRAM                    1362     -                    /run/systemd/journal/socket
# unix  2      [ ACC ]     STREAM     LISTENING     30806    -                    /run/user/1000/keyring/gpg
# unix  2      [ ACC ]     STREAM     LISTENING     30302    2075/pulseaudio      /run/user/1000/pulse/native

