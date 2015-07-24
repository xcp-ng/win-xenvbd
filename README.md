XenVbd - The Xen Paravitual Storage Class Driver for Windows
============================================================

The XenVbd package consists of two single device drivers:

*    xenvbd.sys is a STORPORT miniport driver which attaches to a virtual
     device created by XenBus and creates a child device for each VBD for
     the generic disk driver (disk.sys) to attach to.
     It is also a protocol driver for the blkif wire protocol (see
     include\\xen\\io\\blkif.h).

*    xencrsh.sys is a driver which provides the necessary code to write a
     crashdump out to the paravirtual backend in the event of a BugCheck. 

Quick Start Guide
=================

Building the driver
-------------------

See BUILD.md

Installing the driver
---------------------

See INSTALL.md

Driver Interfaces
=================

See INTERFACES.md

Miscellaneous
=============

For convenience the source repository includes some other scripts:

kdfiles.py
----------

This generates two files called kdfiles32.txt and kdfiles64.txt which can
be used as map files for the .kdfiles WinDBG command.

sdv.py
------

This runs Static Driver Verifier on the source.

clean.py
--------

This removes any files not checked into the repository and not covered by
the .gitignore file.

get_xen_headers.py
------------------

This will import any necessary headers from a given tag of that Xen
repository at git://xenbits.xen.org/xen.git.
