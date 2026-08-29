use k256::{
    elliptic_curve::{
        sec1::{ToEncodedPoint, FromEncodedPoint},
        PrimeField, Field
    },
    ProjectivePoint, Scalar
};
use rand_core::OsRng;

fn main() {
    let r = Scalar::random(&mut OsRng);
    let r_hex = hex::encode(r.to_repr());
    println!("r_hex: {}", r_hex);
    
    let g = ProjectivePoint::GENERATOR;
    let g_hex = hex::encode(g.to_affine().to_encoded_point(true).as_bytes());
    println!("g_hex: {}", g_hex);
    
    let r_bytes = hex::decode(&r_hex).unwrap();
    let r_parsed = Option::from(Scalar::from_repr(*k256::FieldBytes::from_slice(&r_bytes))).unwrap();
    assert_eq!(r, r_parsed);
    
    let g_encoded = k256::EncodedPoint::from_bytes(&hex::decode(&g_hex).unwrap()).unwrap();
    let g_affine = Option::from(k256::AffinePoint::from_encoded_point(&g_encoded)).unwrap();
    assert_eq!(g, ProjectivePoint::from(g_affine));
}
