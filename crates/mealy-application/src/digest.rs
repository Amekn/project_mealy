use sha2::{Digest, Sha256};

/// Canonical algorithm identifier used by the artifact store and persistence schema.
pub const SHA256_ALGORITHM: &str = "sha256";

/// Number of lowercase hexadecimal characters in a SHA-256 digest.
pub const SHA256_DIGEST_HEX_LENGTH: usize = 64;

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Computes the canonical lowercase hexadecimal SHA-256 digest for `content`.
#[must_use]
pub fn sha256_digest(content: &[u8]) -> String {
    Sha256::digest(content)
        .iter()
        .flat_map(|byte| {
            [
                char::from(LOWER_HEX[usize::from(byte >> 4)]),
                char::from(LOWER_HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

/// Returns whether `value` is a canonical lowercase hexadecimal SHA-256 digest.
#[must_use]
pub fn is_sha256_digest(value: &str) -> bool {
    value.len() == SHA256_DIGEST_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{is_sha256_digest, sha256_digest};

    #[test]
    fn sha256_uses_canonical_lowercase_hex() {
        assert_eq!(
            sha256_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(is_sha256_digest(&sha256_digest(b"")));
        assert!(!is_sha256_digest(
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        ));
        assert!(!is_sha256_digest("../artifact"));
    }
}
