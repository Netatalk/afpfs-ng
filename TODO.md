afpfs-ng Improvements
=====================

Command line client
-------------------

* remote filename completion
* completion with BSD's readline
* version detection
* OS guessing

FUSE client
-----------

* readonly mounts aren't supported
* Mount by servername
* integration with avahi/bonjour
* files with '/' in them can't be accessed

AFP 2.x
-------

* non-UTF8 server names aren't supported
* signature in status appears to be broken
* use getsrvrinfo to get connection IP address to make room for AT
* connection recovery
  * open files
  * locked files
* desktop database support
* UTF8 flag is now server-specific, but it should be volume-specific
* non-UTF8 codepage translation

General bugs
------------

* requesting a specific AFP version is unreliable
* filenames have a maximum length of 255, but AFP 3.x allows for much more
* forget username/password after they're used.  Can we actually do this?

* Icon support:
  * full query/result support
  * retrieval tool: a userspace app that can parse icons from resource forks

* Complete implementation of AFP 3.2
  * Extended attributes
  * pretty much every function needs testing and correcting

* AFP 2.x support
  * desktop database support
  * UTF8 flag is now server-specific, but it should be volume-specific
  * non-UTF8 codepage translation
  * lots, lots more

* Authentitcation
  * ClientKRB
  * reconnection
  * Being able to change password
  * Open directory integration

* Ongoing performance tweaking
  * in mknod(), you only need to do the setfiledirparms if the mode or perms
    are different
  * measurements, comparisons to other clients
  * asynchronous unlocking
  * use rx and tx quantums properly
  * queue writes to be one tx quantum
  * optimize locking
  * don't go back through the select loop to read what comes after the DSI
    packet
  * make a preallocated pool of dsi requests
  * make a preallocated pool for dsi messages
  * is_dir function should look in did cache
  * check to see how Mac OS does locking on writes
  * large block writes for FUSE 3.x

* on some clients, such as afpgetstatus, ^C won't work

Development
-----------

* When running afpfsd under gdb, unmount doesn't work because of the use of
  signals

Protocol bugs
-------------

* afpfs-ng doesn't handle the situation where the server is shutdown
* reconnect isn't reliable
* Do DSI buffers get trampled if there's more than one being handled at the
  same time?
* if there is a broken server, the DSI buffers could be overridden
* If a DSI stream gets broken or there's a protocol error, the connection
  should be reset
* We don't currently handle reconnect flags or timeouts for DSI attention
  packets
* for logins, fpLoginExt should be used instead of fpLogin
* for fpCreateFile, use soft creates
* honour volume's HasConfigInfo flag

Mounting
--------

* do correct address/signature matching; right now we don't actually use
  the signature.

Packaging and polish
--------------------

* Make startup scripts (not much point without multi-user support)

Others
------

* rewrite pick_version to do more intelligent guessing for a version number
* after many operations, commands no longer work and neither does ^c
* document API
* shutting down notices aren't honoured
