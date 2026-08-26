# Security

Report vulnerabilities privately through GitHub Security Advisories on the
`absolutejs/key-transparency-providers` repository.

The memory provider is for tests, local examples, and conformance harnesses. It
shares a process and trust domain with its caller, loses all history on restart,
has no independent auditor, and does not implement the IETF KEYTRANS combined
tree, VRF, commitments, monitoring proofs, or privacy protocol. Do not use it to
protect production identities or advertise IETF KEYTRANS interoperability.
