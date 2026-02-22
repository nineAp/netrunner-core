#[derive(Clone, Copy)]
pub struct TlsGroups(pub &'static [u16]);

#[derive(Clone, Copy)]
pub struct TlsSignatures(pub &'static [u16]);

#[derive(Clone, Copy)]
pub struct TlsVersions(pub &'static [u16]);
