use encoding::hex::bin2hex;

// A private key instance.
/// The underlying content is dependent on implementation.
pub struct PrivateKey(pub Vec<u8>);
impl_bytearray!(PrivateKey);

pub struct PublicKey(pub Vec<u8>);
impl_bytearray!(PublicKey);

pub struct SessionKey(pub Vec<u8>);
impl_bytearray!(SessionKey);

pub struct MacKey(pub Vec<u8>);
impl_bytearray!(MacKey);

pub enum KeyPairOption<'a> {
    UseSeed(Vec<u8>),
    FromSecretKey(&'a PrivateKey)
}
