use k256::{ProjectivePoint, Scalar, SecretKey, PublicKey, elliptic_curve::sec1::ToEncodedPoint};
use k256::elliptic_curve::{Field, PrimeField};
use rand_core::OsRng;
use sha2::{Sha256, Digest};

pub struct DLEQProof {
    c: Scalar,
    s: Scalar,
}

impl DLEQProof {
    pub fn generate(
        secret: &Scalar,
        base1: &ProjectivePoint,
        base2: &ProjectivePoint,
        point1: &ProjectivePoint,
        point2: &ProjectivePoint,
    ) -> DLEQProof {
        // Generate random nonce k
        let k = Scalar::random(OsRng);

        // Compute commitments A = k * G, B = k * H
        let a = base1 * &k;
        let b = base2 * &k;

        // Compute challenge c = H(G, H, P, Q, A, B)
        let mut hasher = Sha256::new();
        hasher.update(base1.to_encoded_point(false).as_bytes());
        hasher.update(base2.to_encoded_point(false).as_bytes());
        hasher.update(point1.to_encoded_point(false).as_bytes());
        hasher.update(point2.to_encoded_point(false).as_bytes());
        hasher.update(a.to_affine().to_encoded_point(false).as_bytes());
        hasher.update(b.to_affine().to_encoded_point(false).as_bytes());
        let c_bytes = hasher.finalize();
        let c = Scalar::from_repr(c_bytes.into()).expect("Failed to create scalar from hash");

        // Compute response s = k + c * x
        let s = k + c * secret;

        DLEQProof { c, s }
    }

    pub fn verify(
        &self,
        base1: &ProjectivePoint,
        base2: &ProjectivePoint,
        point1: &ProjectivePoint,
        point2: &ProjectivePoint,
    ) -> bool {
        // Recompute commitments A' = s * G - c * P
        let s_g = base1 * &self.s;
        let c_p = point1 * &self.c;
        let a_prime = s_g - c_p;

        // Recompute commitments B' = s * H - c * Q
        let s_h = base2 * &self.s;
        let c_q = point2 * &self.c;
        let b_prime = s_h - c_q;

        // Recompute challenge c' = H(G, H, P, Q, A', B')
        let mut hasher = Sha256::new();
        hasher.update(base1.to_encoded_point(false).as_bytes());
        hasher.update(base2.to_encoded_point(false).as_bytes());
        hasher.update(point1.to_encoded_point(false).as_bytes());
        hasher.update(point2.to_encoded_point(false).as_bytes());
        hasher.update(a_prime.to_affine().to_encoded_point(false).as_bytes());
        hasher.update(b_prime.to_affine().to_encoded_point(false).as_bytes());
        let c_prime_bytes = hasher.finalize();
        let c_prime = Scalar::from_repr(c_prime_bytes.into()).expect("Failed to create scalar from hash");

        // Check if c' == c
        self.c == c_prime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::{ProjectivePoint, Scalar};
    use rand_core::OsRng;

    #[test]
    fn test_dleq_proof() {
        let secret = Scalar::random(OsRng);
        let base1 = ProjectivePoint::generator();
        let base2 = ProjectivePoint::generator() * Scalar::random(OsRng);
        let point1 = base1 * secret;
        let point2 = base2 * secret;

        let proof = DLEQProof::generate(&secret, &base1, &base2, &point1, &point2);
        assert!(proof.verify(&base1, &base2, &point1, &point2));
    }
}
