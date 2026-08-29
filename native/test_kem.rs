use ml_kem::{KemCore, MlKem768, EncodedSizeUser};
use ml_kem::kem::{EncapsulationKey, DecapsulationKey};

fn main() {
    let pk_bytes = vec![0u8; 1184];
    let arr: &ml_kem::array::Array<u8, _> = pk_bytes.as_slice().try_into().unwrap();
    let ek = EncapsulationKey::<MlKem768>::from_bytes(arr);
    println!("OK");
}
