import os
import logging
from sys import platform

if platform == 'linux':
    import psutil

from . import Exceptions

# Lock file management.
# ref: https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s09.html
#
# Stored in /var/lock:
# The naming convention which must be used is "LCK.." followed by the base name of the device.
# For example, to lock /dev/ttyS0 the file "LCK..ttyS0" would be created.
# HDB UUCP lock file format:
# process identifier (PID) as a ten byte ASCII decimal number, with a trailing newline

def lockpid(lockfile):
    if (os.path.isfile(lockfile)):
        with open(lockfile) as fd:
            lockpid = fd.read()

        try:
            return int(lockpid)
        except:
            logging.info("Lockfile is invalid. Overriding it..")
            os.remove(lockfile)
            return 0

    return 0

def lock(port):
    if platform != 'linux':
        return

    tty = os.path.basename(port)
    lockfile = f'/var/lock/LCK..{tty}'

    lockedpid = lockpid(lockfile)
    if lockedpid:
        if lockedpid == os.getpid():
            return

        if psutil.pid_exists(lockedpid):
            raise Exceptions.LockedException(f"Device {port} is locked")
        else:
            logging.info("Lockfile is stale. Overriding it..")
            os.remove(lockfile)

    fd = open(lockfile, 'w')
    with open(lockfile, 'w') as fd:
        fd.write(f'{os.getpid():10}')

def unlock(port):
    if platform != 'linux':
        return

    tty = os.path.basename(port)
    lockfile = f'/var/lock/LCK..{tty}'

    lockedpid = lockpid(lockfile)
    if lockedpid == os.getpid():
        os.remove(lockfile)
