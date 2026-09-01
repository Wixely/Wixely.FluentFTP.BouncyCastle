# Security

Report vulnerabilities privately to the repository owner before public
disclosure.

The adapter delegates certificate acceptance to FluentFTP's configured
certificate-validation policy. Applications must not enable
`ValidateAnyCertificate` in production unless the network and threat model make
that choice acceptable. Prefer normal PKI validation or an explicit certificate
pin.

`AllowLegacyResumption` permits resuming TLS 1.2 sessions that lack RFC 7627
Extended Master Secret. It is disabled by default and should be enabled only for
a known incompatible server.
