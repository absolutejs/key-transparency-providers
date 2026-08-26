# Security

This provider is an in-process development fixture, not a production security
boundary. The caller, log, monitor, and signing key share one process and one
administrative domain. Restarting the process destroys its history and signing
key. It cannot prove consistency to clients that did not retain a prior view and
cannot detect a split view produced outside its process.
