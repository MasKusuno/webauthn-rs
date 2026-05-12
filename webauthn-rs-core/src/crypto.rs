//! Cryptographic operation wrapper for Webauthn. This module exists to
//! allow ease of auditing, safe operation wrappers for the webauthn library,
//! and cryptographic provider abstraction. This module currently uses OpenSSL
//! as the cryptographic primitive provider.

#![allow(non_camel_case_types)]

use super::error::*;
use crate::proto::*;
use crypto_glue::{
    ecdsa_p256::{
        self, EcdsaP256PublicEncodedPoint, EcdsaP256PublicKey, EcdsaP256Signature,
        EcdsaP256VerifyingKey,
    },
    ecdsa_p384::{
        self, EcdsaP384PublicEncodedPoint, EcdsaP384PublicKey, EcdsaP384Signature,
        EcdsaP384VerifyingKey,
    },
    ecdsa_p521::{
        self,
        EcdsaP521PublicEncodedPoint,
        EcdsaP521PublicKey,
        // EcdsaP521Signature, EcdsaP521VerifyingKey,
    },
    rsa::{BigUint, RS256PublicKey, RS256Signature, RS256VerifyingKey},
    s256, s384, s512,
    traits::{Digest, OwnedToRef, Verifier},
    x509::{self, Certificate, GeneralName, ObjectIdentifier, OtherName, SubjectAltName},
};
// Ed25519 verifier — see workspace Cargo.toml comment on ed25519-dalek.
// crypto-glue 0.1.16 does not surface an Ed25519 verifier so the fork
// pulls ed25519-dalek directly. Verify-only — no signing surface.
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};

/// Validate an x509 signature is valid for the supplied data
pub fn verify_signature(
    certificate: &Certificate,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    let valid = x509::x509_verify_signature(verification_data, signature, certificate)
        .inspect_err(|err| {
            error!(?err, "x509 Verification Error");
        })
        .is_ok();

    Ok(valid)
}

/// Verify a TPM attestation signature (`TpmtSignature::RawSignature`) over
/// `verification_data` using the AIK cert's public key.
///
/// TPM signatures differ from the X.509-signature shape `verify_signature`
/// expects in two ways that matter for the FIDO2 Server conformance Tool's
/// Resp-9 fixtures:
///
///   1. **Raw, not DER.** Per TPMv2-Part2 §11.3.4, the signature inside
///      `TPMT_SIGNATURE` is the raw `r || s` octet pair (ECDSA) or the
///      raw PKCS#1 v1.5 octet string (RSA). `crypto_glue::x509::x509_verify_signature`
///      expects DER-encoded ECDSA signatures and does not match the
///      `RSA_ENCRYPTION` SPKI OID at all (it only routes
///      `SHA_256_WITH_RSA_ENCRYPTION`, which is a *signature* OID, not an
///      SPKI OID — this is a separate upstream bug worth filing).
///   2. **Hash dispatch comes from `alg`.** The AIK cert's SPKI alg is
///      generic (`rsaEncryption` / `id-ecPublicKey`); the COSE `alg` from
///      `attStmt.alg` tells us which digest to apply.
///
/// Implementation:
///   * `alg = ES256` (-7) → P-256 curve, SHA-256 internal, raw 64-byte sig
///   * `alg = ES384` (-35) → P-384 curve, SHA-384 internal, raw 96-byte sig
///   * `alg = RS256` (-257) → RSA-PKCS1 v1.5 + SHA-256
///   * `alg = INSECURE_RS1` (-65535) → RSA-PKCS1 v1.5 + SHA-1 (verifier
///     capability; consumer policy gates whether to enrol)
///
/// The conformance adapter's RS1-acceptance posture (see
/// `posture-rs1-insecure-sha1` in civid spec 013) keeps Resp-9 P-2 green
/// without dragging SHA-1 into production policy.
pub fn verify_tpm_signature(
    alg: COSEAlgorithm,
    certificate: &Certificate,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    use crypto_glue::traits::{EncodeDer, SpkiDecodePublicKey};

    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let spki_der = spki
        .to_der()
        .map_err(|err| {
            error!(?err, "TPM: serialise SPKI to DER");
            WebauthnError::X509DerInvalid
        })?;

    match alg {
        COSEAlgorithm::ES256 => {
            let verifier = EcdsaP256VerifyingKey::from_public_key_der(&spki_der)
                .map_err(|err| {
                    error!(?err, "TPM: AIK SPKI is not P-256 ECDSA");
                    WebauthnError::EcdsaPointInvalid
                })?;
            // P-256 signatures are 32+32 = 64 bytes raw r||s.
            let signature = EcdsaP256Signature::from_slice(signature)
                .map_err(|err| {
                    error!(?err, "TPM: ES256 raw signature length");
                    WebauthnError::SignatureInvalid
                })?;
            Ok(verifier.verify(verification_data, &signature).is_ok())
        }
        COSEAlgorithm::ES384 => {
            let verifier = EcdsaP384VerifyingKey::from_public_key_der(&spki_der)
                .map_err(|err| {
                    error!(?err, "TPM: AIK SPKI is not P-384 ECDSA");
                    WebauthnError::EcdsaPointInvalid
                })?;
            // P-384 signatures are 48+48 = 96 bytes raw r||s.
            let signature = EcdsaP384Signature::from_slice(signature)
                .map_err(|err| {
                    error!(?err, "TPM: ES384 raw signature length");
                    WebauthnError::SignatureInvalid
                })?;
            Ok(verifier.verify(verification_data, &signature).is_ok())
        }
        COSEAlgorithm::RS256 => {
            let verifier = RS256PublicKey::from_public_key_der(&spki_der).map_err(|err| {
                error!(?err, "TPM: AIK SPKI is not RSA");
                WebauthnError::RsaParametersInvalid
            })?;
            let verifier = RS256VerifyingKey::new(verifier);
            let signature = RS256Signature::try_from(signature).map_err(|err| {
                error!(?err, "TPM: RS256 signature length");
                WebauthnError::SignatureInvalid
            })?;
            Ok(verifier.verify(verification_data, &signature).is_ok())
        }
        COSEAlgorithm::INSECURE_RS1 => {
            use crypto_glue::rsa::pkcs1v15::Pkcs1v15Sign;
            use crypto_glue::sha1::Sha1;
            // PKCS#1 v1.5 DigestInfo prefix for SHA-1 (constant from RFC
            // 8017 §9.2). Same constant verify_signature uses for the
            // RsaS256+INSECURE_RS1 path on the assertion side.
            const SHA1_DIGEST_INFO_PREFIX: [u8; 15] = [
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
                0x04, 0x14,
            ];
            let pub_key = RS256PublicKey::from_public_key_der(&spki_der).map_err(|err| {
                error!(?err, "TPM: AIK SPKI is not RSA");
                WebauthnError::RsaParametersInvalid
            })?;
            let scheme = Pkcs1v15Sign {
                hash_len: Some(20),
                prefix: Box::from(&SHA1_DIGEST_INFO_PREFIX[..]),
            };
            let mut hasher = Sha1::new();
            hasher.update(verification_data);
            let hashed = hasher.finalize();
            Ok(pub_key.verify(scheme, &hashed, signature).is_ok())
        }
        other => {
            error!(?other, "TPM verify: unsupported alg");
            Err(WebauthnError::COSEKeyInvalidAlgorithm)
        }
    }
}

pub(crate) struct TpmSanData<'a> {
    pub manufacturer: &'a str,
    pub _model: &'a str,
    pub _version: &'a str,
}

#[derive(Default)]
struct TpmSanDataBuilder<'a> {
    manufacturer: Option<&'a str>,
    model: Option<&'a str>,
    version: Option<&'a str>,
}

impl<'a> TpmSanDataBuilder<'a> {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn manufacturer(mut self, value: &'a str) -> Self {
        self.manufacturer = Some(value);
        self
    }

    pub(crate) fn model(mut self, value: &'a str) -> Self {
        self.model = Some(value);
        self
    }

    pub(crate) fn version(mut self, value: &'a str) -> Self {
        self.version = Some(value);
        self
    }

    pub(crate) fn build(self) -> WebauthnResult<TpmSanData<'a>> {
        self.manufacturer
            .zip(self.model)
            .zip(self.version)
            .map(|((manufacturer, model), version)| TpmSanData {
                manufacturer,
                _model: model,
                _version: version,
            })
            .ok_or(WebauthnError::AttestationCertificateRequirementsNotMet)
    }
}

// pub(crate) const TCG_AT_TPM_MANUFACTURER: Oid = der_parser::oid!(2.23.133 .2 .1);
// pub(crate) const TCG_AT_TPM_MODEL: Oid = der_parser::oid!(2.23.133 .2 .2);
// pub(crate) const TCG_AT_TPM_VERSION: Oid = der_parser::oid!(2.23.133 .2 .3);

pub(crate) const TCG_AT_TPM_MANUFACTURER_RAW: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.2.1");
pub(crate) const TCG_AT_TPM_MODEL_RAW: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.2.2");
pub(crate) const TCG_AT_TPM_VERSION_RAW: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.2.3");

impl<'a> TryFrom<&'a SubjectAltName> for TpmSanData<'a> {
    type Error = WebauthnError;

    fn try_from(x509_name: &'a SubjectAltName) -> Result<Self, Self::Error> {
        // Per TCG EK Profile §3.2.9 / TPM AIK §8.3.1, the manufacturer /
        // model / firmware-version attributes can appear in the SAN under
        // either of two GeneralName encodings:
        //
        //   * `OtherName` — `[0] OtherName { type-id = OID, value = ANY }`,
        //     each OID/value pair as its own GeneralName entry. Real TPM
        //     vendor AIKs we tested here historically use this form.
        //   * `DirectoryName` — `[4] Name`, an RdnSequence carrying the
        //     same attributes via `AttributeTypeAndValue { oid, value }`.
        //     The FIDO2 Server Conformance Tool's `tpmAIK.js` /
        //     `tpmECC.js` fixtures emit this form.
        //
        // Both encodings are spec-valid (TCG EK Profile lists both). The
        // upstream parser only handled `OtherName`, which silently failed
        // every TPM AIK with a `DirectoryName`-style SAN — including the
        // FIDO2 Server Conformance Tool's Resp-9 P-1 / P-2 fixtures.
        // Walk both forms.
        x509_name
            .0
            .iter()
            .try_fold(TpmSanDataBuilder::new(), |builder, general_name| {
                let next = match general_name {
                    GeneralName::OtherName(OtherName { type_id, value }) => {
                        if *type_id == TCG_AT_TPM_MANUFACTURER_RAW {
                            let attr_value = str::from_utf8(value.value())?;
                            builder.manufacturer(attr_value)
                        } else if *type_id == TCG_AT_TPM_MODEL_RAW {
                            let attr_value = str::from_utf8(value.value())?;
                            builder.model(attr_value)
                        } else if *type_id == TCG_AT_TPM_VERSION_RAW {
                            let attr_value = str::from_utf8(value.value())?;
                            builder.version(attr_value)
                        } else {
                            builder
                        }
                    }
                    GeneralName::DirectoryName(rdn_seq) => {
                        // RdnSequence ::= SEQUENCE OF RelativeDistinguishedName
                        // RelativeDistinguishedName ::= SET SIZE(1..MAX) OF AttributeTypeAndValue
                        // We accept both flat shapes (one AVA per RDN, FIDO Tool
                        // emits this) and clustered shapes (multiple AVAs in
                        // one RDN, also spec-valid).
                        rdn_seq.0.iter().try_fold(builder, |inner_builder, rdn| {
                            rdn.0.iter().try_fold(inner_builder, |b, ava| {
                                let oid = &ava.oid;
                                let bytes = ava.value.value();
                                let attr_value = str::from_utf8(bytes)?;
                                Ok::<_, std::str::Utf8Error>(
                                    if *oid == TCG_AT_TPM_MANUFACTURER_RAW {
                                        b.manufacturer(attr_value)
                                    } else if *oid == TCG_AT_TPM_MODEL_RAW {
                                        b.model(attr_value)
                                    } else if *oid == TCG_AT_TPM_VERSION_RAW {
                                        b.version(attr_value)
                                    } else {
                                        b
                                    },
                                )
                            })
                        })?
                    }
                    _ => builder,
                };
                Ok(next)
            })
            .map_err(|_: std::str::Utf8Error| WebauthnError::ParseNOMFailure)
            .and_then(TpmSanDataBuilder::build)
    }
}

/// Hash `input` with the digest implied by the COSE signing algorithm `alg`.
///
/// Used by the TPM attestation verifier (WebAuthn §8.3 step "Verify that
/// extraData is set to the hash of attToBeSigned using the hash algorithm
/// employed in alg"). The hash size maps directly off the alg:
///
/// * `ES256` / `RS256` / `PS256` → SHA-256
/// * `ES384` / `RS384` / `PS384` → SHA-384
/// * `ES512` / `RS512` / `PS512` → SHA-512
/// * `INSECURE_RS1` → SHA-1
///
/// SHA-1 is recognised here as a **verifier capability**, not a
/// recommendation: the function answers the question "what digest does
/// alg-N imply" and an RP's policy layer (`secure_algs()`, tenant
/// allowlists, AAL profile) decides whether a credential signed with
/// alg-N may be enrolled. `EDDSA` and `PinUvProtocol` do not appear in
/// TPM signing algorithms and return `COSEKeyInvalidType`.
pub(crate) fn only_hash_from_type(
    alg: COSEAlgorithm,
    input: &[u8],
) -> Result<Vec<u8>, WebauthnError> {
    use crypto_glue::sha1::Sha1;
    match alg {
        COSEAlgorithm::ES256 | COSEAlgorithm::RS256 | COSEAlgorithm::PS256 => {
            let mut hasher = s256::Sha256::new();
            hasher.update(input);
            Ok(hasher.finalize().to_vec())
        }
        COSEAlgorithm::ES384 | COSEAlgorithm::RS384 | COSEAlgorithm::PS384 => {
            let mut hasher = s384::Sha384::new();
            hasher.update(input);
            Ok(hasher.finalize().to_vec())
        }
        COSEAlgorithm::ES521 | COSEAlgorithm::RS512 | COSEAlgorithm::PS512 => {
            let mut hasher = s512::Sha512::new();
            hasher.update(input);
            Ok(hasher.finalize().to_vec())
        }
        COSEAlgorithm::INSECURE_RS1 => {
            let mut hasher = Sha1::new();
            hasher.update(input);
            Ok(hasher.finalize().to_vec())
        }
        c_alg => {
            debug!(?c_alg, "WebauthnError::COSEKeyInvalidType");
            Err(WebauthnError::COSEKeyInvalidType)
        }
    }
}

impl TryFrom<&serde_cbor_2::Value> for COSEKey {
    type Error = WebauthnError;
    fn try_from(d: &serde_cbor_2::Value) -> Result<COSEKey, Self::Error> {
        let m = cbor_try_map!(d)?;

        // See also https://tools.ietf.org/html/rfc8152#section-3.1
        // These values look like:
        // Object({
        //     // negative (-) values are per-algo specific
        //     Integer(-3): Bytes([48, 185, 178, 204, 113, 186, 105, 138, 190, 33, 160, 46, 131, 253, 100, 177, 91, 243, 126, 128, 245, 119, 209, 59, 186, 41, 215, 196, 24, 222, 46, 102]),
        //     Integer(-2): Bytes([158, 212, 171, 234, 165, 197, 86, 55, 141, 122, 253, 6, 92, 242, 242, 114, 158, 221, 238, 163, 127, 214, 120, 157, 145, 226, 232, 250, 144, 150, 218, 138]),
        //     Integer(-1): U64(1),
        //     Integer(1): U64(2), // algorithm identifier
        //     Integer(3): I64(-7) // content type see https://tools.ietf.org/html/rfc8152#section-8.1 -7 being ES256 + SHA256
        // })
        // Now each of these integers has a specific meaning, and you need to parse them in order.
        // First, value 1 for the key type.

        let key_type_value = m
            .get(&serde_cbor_2::Value::Integer(1))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let key_type = cbor_try_i128!(key_type_value)?;
        /*
            // Some keys may return this as a string rather than int.
            // The only key so far is the solokey and it's ed25519 support
            // is broken, so there isn't much point enabling this today.
            .or_else(|_| {
                // tstr is also supported as a type on this field.
                cbor_try_string!(key_type_value)
                    .and_then(|kt_str| {
                        match kt_str.as_str() {
                            "OKP" => Ok(1),
                            "EC2" => Ok(2),
                            "RSA" => Ok(3),
                            _ => Err(WebauthnError::COSEKeyInvalidCBORValue)
                        }
                    })
            })?;
        */

        let content_type_value = m
            .get(&serde_cbor_2::Value::Integer(3))
            .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
        let content_type = cbor_try_i128!(content_type_value)?;

        let type_ = COSEAlgorithm::try_from(content_type)
            .map_err(|_| WebauthnError::COSEKeyInvalidAlgorithm)?;

        // https://www.iana.org/assignments/cose/cose.xhtml
        // https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples
        // match key_type {
        // 1 => {} OctetKey
        if key_type == (COSEKeyTypeId::EC_EC2 as i128)
            && (type_ == COSEAlgorithm::ES256
                || type_ == COSEAlgorithm::ES384
                || type_ == COSEAlgorithm::ES521)
        {
            // This indicates this is an EC2 key consisting of crv, x, y, which are stored in
            // crv (-1), x (-2) and y (-3)
            // Get these values now ....

            let curve_type_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let curve_type = cbor_try_i128!(curve_type_value)?;

            let curve = ECDSACurve::try_from(curve_type)?;

            let x_value = m
                .get(&serde_cbor_2::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let x = cbor_try_bytes!(x_value)?;

            let y_value = m
                .get(&serde_cbor_2::Value::Integer(-3))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let y = cbor_try_bytes!(y_value)?;

            let coord_len = curve.coordinate_size();
            if x.len() != coord_len || y.len() != coord_len {
                return Err(WebauthnError::COSEKeyECDSAXYInvalid);
            }

            // Right, now build the struct.
            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::EC_EC2(COSEEC2Key {
                    curve,
                    x: x.to_vec(),
                    y: y.to_vec(),
                }),
            };

            // The rfc additionally states:
            //   "   Applications MUST check that the curve and the key type are
            //     consistent and reject a key if they are not."
            // this means feeding the values to openssl to validate them for us!

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::EC_RSA as i128)
            && (type_ == COSEAlgorithm::RS256 || type_ == COSEAlgorithm::INSECURE_RS1)
        {
            // RSAKey
            //
            // Valid modulus lengths expressed in bytes: 128 (RSA-1024),
            // 256 (RSA-2048), 384 (RSA-3072), 512 (RSA-4096). The RSA-2048
            // fixture is what production WebAuthn deployments ship; the
            // shorter variants are retained so the verifier can inspect
            // legacy-shape attestations (WebAuthn L1 interop harnesses,
            // TPM INSECURE_RS1 fixtures from the FIDO Conformance Tool).
            // Policy on whether such a credential is accepted lives in
            // the consumer — `secure_algs()` omits RS1, and AAL profiles
            // further restrict modulus size independently of this parser.
            //
            // -37 -> PS256
            // -257 -> RS256 aka RSASSA-PKCS1-v1_5 with SHA-256
            // -65535 -> INSECURE_RS1 aka RSASSA-PKCS1-v1_5 with SHA-1

            let n_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let n = cbor_try_bytes!(n_value)?;

            let e_value = m
                .get(&serde_cbor_2::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let e = cbor_try_bytes!(e_value)?;

            if !matches!(n.len(), 128 | 256 | 384 | 512) || e.len() != 3 {
                return Err(WebauthnError::COSEKeyRSANEInvalid);
            }

            // Set the n and e, we know they are proper sizes.
            let mut e_temp = [0; 3];
            e_temp.copy_from_slice(e.as_slice());

            // Right, now build the struct.
            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::RSA(COSERSAKey {
                    n: n.to_vec(),
                    e: e_temp,
                }),
            };

            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::EC_OKP as i128) && (type_ == COSEAlgorithm::EDDSA) {
            // https://datatracker.ietf.org/doc/html/rfc8152#section-13.2

            let curve_type_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let curve = cbor_try_i128!(curve_type_value).and_then(EDDSACurve::try_from)?;

            /*
                // Some keys may return this as a string rather than int.
                // The only key so far is the solokey and it's ed25519 support
                // is broken, so there isn't much point enabling this today.
                .or_else(|_| {
                    // tstr is also supported as a type on this field.
                    cbor_try_string!(curve_type_value)
                        .and_then(|ct_str| {
                            trace!(?ct_str);
                            match ct_str.as_str() {
                                "EdDSA" => Ok(-8),
                                _ => Err(WebauthnError::COSEKeyInvalidCBORValue)
                            }
                        })
                })?;
            */

            let x_value = m
                .get(&serde_cbor_2::Value::Integer(-2))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let x = cbor_try_bytes!(x_value)?;

            if x.len() != curve.coordinate_size() {
                return Err(WebauthnError::COSEKeyEDDSAXInvalid);
            }

            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::EC_OKP(COSEOKPKey {
                    curve,
                    x: x.to_vec(),
                }),
            };

            // The rfc additionally states:
            //   "   Applications MUST check that the curve and the key type are
            //     consistent and reject a key if they are not."
            // this means feeding the values to openssl to validate them for us!
            cose_key.validate()?;
            // return it
            Ok(cose_key)
        } else if key_type == (COSEKeyTypeId::AKP as i128)
            && matches!(
                type_,
                COSEAlgorithm::ML_DSA_44 | COSEAlgorithm::ML_DSA_65 | COSEAlgorithm::ML_DSA_87
            )
        {
            // draft-ietf-cose-dilithium §5 — AKP key type for ML-DSA. Single
            // public-key member at label -1 carrying raw FIPS 204 encoded bytes.
            // The outer `if` already narrows `type_` to one of these three
            // ML-DSA variants; the wildcard arm is unreachable in practice
            // but spelt as a real Err so clippy's `deny(clippy::unreachable)`
            // (under `deny(warnings)`) can see through the guard.
            let param_set = match type_ {
                COSEAlgorithm::ML_DSA_44 => MlDsaParamSet::MlDsa44,
                COSEAlgorithm::ML_DSA_65 => MlDsaParamSet::MlDsa65,
                COSEAlgorithm::ML_DSA_87 => MlDsaParamSet::MlDsa87,
                _ => return Err(WebauthnError::COSEKeyInvalidType),
            };

            let pk_value = m
                .get(&serde_cbor_2::Value::Integer(-1))
                .ok_or(WebauthnError::COSEKeyInvalidCBORValue)?;
            let pk_bytes = cbor_try_bytes!(pk_value)?;

            if pk_bytes.len() != param_set.public_key_len() {
                debug!(
                    expected = param_set.public_key_len(),
                    actual = pk_bytes.len(),
                    "ML-DSA public key length mismatch"
                );
                return Err(WebauthnError::COSEKeyInvalidType);
            }

            let cose_key = COSEKey {
                type_,
                key: COSEKeyType::ML_DSA(COSEMlDsaKey {
                    param_set,
                    public_key: pk_bytes.to_vec(),
                }),
            };
            cose_key.validate()?;
            Ok(cose_key)
        } else {
            debug!(?key_type, ?type_, "WebauthnError::COSEKeyInvalidType");
            Err(WebauthnError::COSEKeyInvalidType)
        }
    }
}

impl TryFrom<(COSEAlgorithm, &Certificate)> for COSEKey {
    type Error = WebauthnError;

    fn try_from((alg, certificate): (COSEAlgorithm, &Certificate)) -> Result<COSEKey, Self::Error> {
        let subject_public_key_info = certificate
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();

        let key = match alg {
            COSEAlgorithm::ES256 => {
                let pub_key = EcdsaP256PublicKey::try_from(subject_public_key_info)
                    .map_err(|_err| WebauthnError::CertificatePublicKeyAlgorthimMismatch)?;

                let point = EcdsaP256PublicEncodedPoint::from(pub_key);

                let Some(xbn) = point.x().map(|x| x.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                let Some(ybn) = point.y().map(|y| y.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP256R1,
                    x: xbn,
                    y: ybn,
                }))
            }

            COSEAlgorithm::ES384 => {
                let pub_key = EcdsaP384PublicKey::try_from(subject_public_key_info)
                    .map_err(|_err| WebauthnError::CertificatePublicKeyAlgorthimMismatch)?;

                let point = EcdsaP384PublicEncodedPoint::from(pub_key);

                let Some(xbn) = point.x().map(|x| x.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                let Some(ybn) = point.y().map(|y| y.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP384R1,
                    x: xbn,
                    y: ybn,
                }))
            }
            COSEAlgorithm::ES521 => {
                let pub_key = EcdsaP521PublicKey::try_from(subject_public_key_info)
                    .map_err(|_err| WebauthnError::CertificatePublicKeyAlgorthimMismatch)?;

                let point = EcdsaP521PublicEncodedPoint::from(pub_key);

                let Some(xbn) = point.x().map(|x| x.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                let Some(ybn) = point.y().map(|y| y.to_vec()) else {
                    return Err(WebauthnError::EcdsaPointInvalid);
                };

                Ok(COSEKeyType::EC_EC2(COSEEC2Key {
                    curve: ECDSACurve::SECP521R1,
                    x: xbn,
                    y: ybn,
                }))
            }

            COSEAlgorithm::RS256
            | COSEAlgorithm::RS384
            | COSEAlgorithm::RS512
            | COSEAlgorithm::PS256
            | COSEAlgorithm::PS384
            | COSEAlgorithm::PS512
            | COSEAlgorithm::EDDSA
            | COSEAlgorithm::PinUvProtocol
            | COSEAlgorithm::INSECURE_RS1
            | COSEAlgorithm::ML_DSA_44
            | COSEAlgorithm::ML_DSA_65
            | COSEAlgorithm::ML_DSA_87 => {
                error!(
                    "unsupported X509 to COSE conversion for COSE algorithm type {:?}",
                    alg
                );
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }?;

        Ok(COSEKey { type_: alg, key })
    }
}

enum COSEKeyPublic {
    EcdsaP256(EcdsaP256PublicKey),
    EcdsaP384(EcdsaP384PublicKey),
    EcdsaP521(EcdsaP521PublicKey),
    RsaS256(RS256PublicKey),
    Ed25519(Ed25519VerifyingKey),
    // Ed448(),
}

impl COSEKey {
    pub(crate) fn get_alg_key_ecc_x962_raw(&self) -> Result<Vec<u8>, WebauthnError> {
        // Let publicKeyU2F be the concatenation 0x04 || x || y.
        // Note: This signifies uncompressed ECC key format.
        match &self.key {
            COSEKeyType::EC_EC2(ecpk) => {
                let r: [u8; 1] = [0x04];
                Ok(r.iter()
                    .chain(ecpk.x.iter())
                    .chain(ecpk.y.iter())
                    .copied()
                    .collect())
            }
            _ => {
                debug!("get_alg_key_ecc_x962_raw");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), WebauthnError> {
        // ML-DSA validation is length-only at decode time; the actual
        // public-key math is verified lazily inside the ml-dsa crate's
        // `VerifyingKey::decode`. Skip the get_public_key round-trip which
        // does not represent ML-DSA keys.
        if matches!(&self.key, COSEKeyType::ML_DSA(_)) {
            return Ok(());
        }
        self.get_public_key().map(|_| ())
    }

    /// Retrieve the public key of this COSEKey as an OpenSSL structure
    fn get_public_key(&self) -> Result<COSEKeyPublic, WebauthnError> {
        match &self.key {
            COSEKeyType::EC_EC2(ec2k) => match ec2k.curve {
                ECDSACurve::SECP256R1 => {
                    ecdsa_p256::from_coords_raw(ec2k.x.as_ref(), ec2k.y.as_ref())
                        .map(COSEKeyPublic::EcdsaP256)
                        .ok_or(WebauthnError::EcdsaPointInvalid)
                }
                ECDSACurve::SECP384R1 => {
                    ecdsa_p384::from_coords_raw(ec2k.x.as_ref(), ec2k.y.as_ref())
                        .map(COSEKeyPublic::EcdsaP384)
                        .ok_or(WebauthnError::EcdsaPointInvalid)
                }
                ECDSACurve::SECP521R1 => {
                    ecdsa_p521::from_coords_raw(ec2k.x.as_ref(), ec2k.y.as_ref())
                        .map(COSEKeyPublic::EcdsaP521)
                        .ok_or(WebauthnError::EcdsaPointInvalid)
                }
            },
            COSEKeyType::RSA(rsak) => {
                let n = BigUint::from_bytes_be(&rsak.n);
                let e = BigUint::from_bytes_be(&rsak.e);

                RS256PublicKey::new(n, e)
                    .map(COSEKeyPublic::RsaS256)
                    .map_err(|_err| WebauthnError::RsaParametersInvalid)
            }
            COSEKeyType::EC_OKP(edk) => {
                // EdDSA verifying-key construction. ed25519-dalek's
                // VerifyingKey::from_bytes takes the 32-byte compressed
                // public key per RFC 8032 §5.1.3, which is exactly what
                // CTAP packs into `x` for the OKP key. Ed448 stays
                // unsupported (no audited pure-Rust Ed448 verifier as of
                // 2026-Q2; not advertised by civid's production listener).
                match &edk.curve {
                    EDDSACurve::ED25519 => {
                        let xref: &[u8] = edk.x.as_ref();
                        let bytes: [u8; 32] = xref.try_into().map_err(|_err| {
                            error!(len = xref.len(), "Ed25519 x is not 32 bytes");
                            WebauthnError::COSEKeyEDDSAXInvalid
                        })?;
                        Ed25519VerifyingKey::from_bytes(&bytes)
                            .map(COSEKeyPublic::Ed25519)
                            .map_err(|err| {
                                error!(?err, "Ed25519 VerifyingKey::from_bytes");
                                WebauthnError::COSEKeyEDDSAXInvalid
                            })
                    }
                    EDDSACurve::ED448 => Err(WebauthnError::SshPublicKeyEDUnsupported),
                }
            }
            COSEKeyType::ML_DSA(_) => {
                // ML-DSA is PQC and has no COSEKeyPublic representation.
                // Callers that need to verify an ML-DSA signature must route
                // through `verify_signature` which dispatches separately.
                debug!("ML-DSA key has no public-key representation in COSEKeyPublic");
                Err(WebauthnError::COSEKeyInvalidType)
            }
        }
    }

    /// Verifies data was signed with this [COSEKey].
    pub fn verify_signature(
        &self,
        signature: &[u8],
        verification_data: &[u8],
    ) -> Result<bool, WebauthnError> {
        if let COSEKeyType::ML_DSA(ml_key) = &self.key {
            return ml_dsa_verify_signature(ml_key, signature, verification_data);
        }
        let public_key = self.get_public_key()?;

        match public_key {
            COSEKeyPublic::EcdsaP256(pub_key) => {
                let signature = EcdsaP256Signature::from_der(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = EcdsaP256VerifyingKey::from(&pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
            COSEKeyPublic::EcdsaP384(pub_key) => {
                let signature = EcdsaP384Signature::from_der(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = EcdsaP384VerifyingKey::from(&pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
            COSEKeyPublic::EcdsaP521(_pub_key) => {
                // Currently this is unsupported by p521 but will be available
                // in future. There really isn't *huge* reason to use p521 anyway,
                // so for now we disable this and move on.
                /*
                let signature = EcdsaP521Signature::from_der(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = EcdsaP521VerifyingKey::from(&pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
                */
                Ok(false)
            }
            COSEKeyPublic::RsaS256(pub_key) => {
                // INSECURE_RS1 (COSE alg -65535): RSASSA-PKCS1-v1_5 over
                // SHA-1. Recognised here as a verifier capability — see
                // `only_hash_from_type`'s rationale. Policy gating still
                // applies at the consumer (`secure_algs()` omits RS1).
                if self.type_ == COSEAlgorithm::INSECURE_RS1 {
                    use crypto_glue::rsa::pkcs1v15::Pkcs1v15Sign;
                    use crypto_glue::sha1::Sha1;
                    use crypto_glue::traits::Digest;

                    // PKCS#1 v1.5 DigestInfo DER encoding for SHA-1. RFC 3447
                    // / RFC 8017 §9.2 — fixed 15-byte prefix prepended to the
                    // 20-byte SHA-1 digest before RSA-modular-exp verification.
                    // crypto-glue does not enable the `oid` feature on
                    // `sha1::Sha1` so `Pkcs1v15Sign::new::<Sha1>()` (which
                    // resolves the prefix from `AssociatedOid`) is unavailable;
                    // the constant below is the canonical DigestInfo bytes.
                    const SHA1_DIGEST_INFO_PREFIX: [u8; 15] = [
                        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
                        0x00, 0x04, 0x14,
                    ];
                    let scheme = Pkcs1v15Sign {
                        hash_len: Some(20),
                        prefix: Box::from(&SHA1_DIGEST_INFO_PREFIX[..]),
                    };
                    let mut hasher = Sha1::new();
                    hasher.update(verification_data);
                    let hashed = hasher.finalize();
                    return Ok(pub_key.verify(scheme, &hashed, signature).is_ok());
                }
                let signature = RS256Signature::try_from(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                let verifier = RS256VerifyingKey::new(pub_key);
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
            COSEKeyPublic::Ed25519(verifier) => {
                // RFC 8032 §5.1.6 / WebAuthn §6.5.6: EdDSA signatures are a
                // fixed 64-byte octet string (32-byte R || 32-byte S),
                // verified directly over `verification_data` (the message,
                // not a digest — Ed25519 hashes internally via SHA-512).
                let signature = Ed25519Signature::from_slice(signature)
                    .map_err(|_err| WebauthnError::SignatureInvalid)?;
                Ok(verifier.verify(verification_data, &signature).is_ok())
            }
        }
    }
}

/// Verify a WebAuthn assertion signature using an ML-DSA (FIPS 204) public key.
///
/// civid feature 027 PoC — dispatches to the RustCrypto `ml-dsa` crate. The
/// signature is produced per draft-ietf-cose-dilithium: raw FIPS 204 sigma
/// with empty context, covering `authenticatorData || SHA256(clientDataJSON)`
/// (for assertion) or the attestation-specific message (for attestation).
///
/// REWRITE-ON-BUMP(ml-dsa>=0.1): watch for `VerifyingKey::decode` /
/// `Signature::decode` / `verify_with_context` API renames when the crate
/// bumps to 0.1.x. The `signature::Verifier::verify` trait call path is a
/// more stable alternative; see lib.rs:626-632 in ml-dsa 0.0.4.
#[cfg(feature = "ml-dsa")]
fn ml_dsa_verify_signature(
    cose_key: &COSEMlDsaKey,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    use ml_dsa::signature::Verifier;
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey};
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature, VerifyingKey};

    if signature.len() != cose_key.param_set.signature_len() {
        debug!(
            expected = cose_key.param_set.signature_len(),
            actual = signature.len(),
            "ML-DSA signature length mismatch"
        );
        return Ok(false);
    }
    if cose_key.public_key.len() != cose_key.param_set.public_key_len() {
        debug!(
            expected = cose_key.param_set.public_key_len(),
            actual = cose_key.public_key.len(),
            "ML-DSA public key length mismatch at verify time"
        );
        return Err(WebauthnError::COSEKeyInvalidType);
    }

    let ok = match cose_key.param_set {
        MlDsaParamSet::MlDsa44 => {
            let pk_enc = EncodedVerifyingKey::<MlDsa44>::try_from(cose_key.public_key.as_slice())
                .map_err(|_| WebauthnError::COSEKeyInvalidType)?;
            let sig_enc = EncodedSignature::<MlDsa44>::try_from(signature)
                .map_err(|_| WebauthnError::COSEKeyInvalidType)?;
            let vk = VerifyingKey::<MlDsa44>::decode(&pk_enc);
            let sig =
                Signature::<MlDsa44>::decode(&sig_enc).ok_or(WebauthnError::COSEKeyInvalidType)?;
            vk.verify(verification_data, &sig).is_ok()
        }
        MlDsaParamSet::MlDsa65 => {
            let pk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(cose_key.public_key.as_slice())
                .map_err(|_| WebauthnError::COSEKeyInvalidType)?;
            let sig_enc = EncodedSignature::<MlDsa65>::try_from(signature)
                .map_err(|_| WebauthnError::COSEKeyInvalidType)?;
            let vk = VerifyingKey::<MlDsa65>::decode(&pk_enc);
            let sig =
                Signature::<MlDsa65>::decode(&sig_enc).ok_or(WebauthnError::COSEKeyInvalidType)?;
            vk.verify(verification_data, &sig).is_ok()
        }
        MlDsaParamSet::MlDsa87 => {
            let pk_enc = EncodedVerifyingKey::<MlDsa87>::try_from(cose_key.public_key.as_slice())
                .map_err(|_| WebauthnError::COSEKeyInvalidType)?;
            let sig_enc = EncodedSignature::<MlDsa87>::try_from(signature)
                .map_err(|_| WebauthnError::COSEKeyInvalidType)?;
            let vk = VerifyingKey::<MlDsa87>::decode(&pk_enc);
            let sig =
                Signature::<MlDsa87>::decode(&sig_enc).ok_or(WebauthnError::COSEKeyInvalidType)?;
            vk.verify(verification_data, &sig).is_ok()
        }
    };
    Ok(ok)
}

/// Stub invoked when `ml-dsa` Cargo feature is off. Present so the dispatch
/// in `COSEKey::verify_signature` compiles regardless of feature selection.
#[cfg(not(feature = "ml-dsa"))]
fn ml_dsa_verify_signature(
    _cose_key: &COSEMlDsaKey,
    _signature: &[u8],
    _verification_data: &[u8],
) -> Result<bool, WebauthnError> {
    error!("ML-DSA verify attempted but `ml-dsa` Cargo feature is disabled");
    Err(WebauthnError::COSEKeyInvalidType)
}

/// Compute the sha256 of a slice of data.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = s256::Sha256::new();
    hasher.update(data);
    *hasher.finalize().as_ref()
}

/// Compute the sha384 of a slice of data.
pub fn compute_sha384(data: &[u8]) -> [u8; 48] {
    let mut hasher = s384::Sha384::new();
    hasher.update(data);
    *hasher.finalize().as_ref()
}

/// Compute the sha512 of a slice of data.
pub fn compute_sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = s512::Sha512::new();
    hasher.update(data);
    *hasher.finalize().as_ref()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic)]

    use super::*;
    use hex_literal::hex;
    use serde_cbor_2::Value;

    #[test]
    fn cbor_es256() {
        let hex_data = hex!(
                "A5"         // Map - 5 elements
                "01 02"      //   1:   2,  ; kty: EC2 key type
                "03 26"      //   3:  -7,  ; alg: ES256 signature algorithm
                "20 01"      //  -1:   1,  ; crv: P-256 curve
                "21 58 20   65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d" // -2:   x,  ; x-coordinate
                "22 58 20   1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c" // -3:   y,  ; y-coordinate
        );

        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES256);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP256R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    #[test]
    fn cbor_es384() {
        let hex_data = hex!(
                "A5"         // Map - 5 elements
                "01 02"      //   1:   2,  ; kty: EC2 key type
                "03 38 22"   //   3:  -35,  ; alg: ES384 signature algorithm
                "20 02"      //  -1:   2,  ; crv: P-384 curve
                "21 58 30   ceeaf818731db7af2d02e029854823d71bdbf65fb0c6ff69" // -2: x, ; x-coordinate
                           "42c9cf891efe18ea81430517d777f5c43550da801be5bf2f"
                "22 58 30   dda1d0ead72e042efb7c36a38cc021abb2ca1a2e38159edd" // -3: y ; y-coordinate
                           "a8c25f391e9a38d79dd56b9427d1c7c70cfa778ab849b087"
        );

        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES384);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!(
                        "ceeaf818731db7af2d02e029854823d71bdbf65fb0c6ff69
                         42c9cf891efe18ea81430517d777f5c43550da801be5bf2f"
                    )
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!(
                        "dda1d0ead72e042efb7c36a38cc021abb2ca1a2e38159edd
                         a8c25f391e9a38d79dd56b9427d1c7c70cfa778ab849b087"
                    )
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP384R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    #[test]
    fn cbor_es512() {
        let hex_data = hex!(
                "A5"         // Map - 5 elements
                "01 02"      //   1:   2,  ; kty: EC2 key type
                "03 38 23"   //   3:  -36,  ; alg: ES512 signature algorithm
                "20 03"      //  -1:   3,  ; crv: P-521 curve
                "21 58 42   0106cfaacf34b13f24bbb2f806fd9cfacff9a2a5ef9ecfcd85664609a0b2f6d4fd" // -2:   x,  ; x-coordinate
                           "b8e1d58630905f13f38d8eed8714eceb716920a3a235581623261fed961f7b7d72"
                "22 58 42   0089597a052a8d3c8b2b5692d467dea19f8e1b9ca17fa563a1a826855dade04811" // -3:   y,  ; y-coordinate
                           "b2881819e72f1706daeaf7d3773b2e284983a0eec33c2fe3ff5697722e95b29536");

        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();

        assert_eq!(key.type_, COSEAlgorithm::ES521);
        match key.key {
            COSEKeyType::EC_EC2(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!(
                        "0106cfaacf34b13f24bbb2f806fd9cfacff9a2a5ef9ecfcd85664609a0b2f6d4fd
                         b8e1d58630905f13f38d8eed8714eceb716920a3a235581623261fed961f7b7d72"
                    )
                );
                assert_eq!(
                    pkey.y.as_ref(),
                    hex!(
                        "0089597a052a8d3c8b2b5692d467dea19f8e1b9ca17fa563a1a826855dade04811
                         b2881819e72f1706daeaf7d3773b2e284983a0eec33c2fe3ff5697722e95b29536"
                    )
                );
                assert_eq!(pkey.curve, ECDSACurve::SECP521R1);
            }
            _ => panic!("Key should be parsed EC2 key"),
        }
    }

    /*
    #[test]
    fn cbor_ed25519() {
        let hex_data = hex!(
        "A4"         // Map - 4 elements
        "01 01"      //   1:   1,  ; kty: OKP key type
        "03 27"      //   3:  -8,  ; alg: EDDSA signature algorithm
        "20 06"      //  -1:   6,  ; crv: Ed25519 curve
        "21 58 20   43565027f918beb00257d112b903d15b93f5cbc7562dfc8458fbefd714546e3c" // -2:   x,  ; Y-coordinate
        );
        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();
        assert_eq!(key.type_, COSEAlgorithm::EDDSA);
        match key.key {
            COSEKeyType::EC_OKP(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("43565027f918beb00257d112b903d15b93f5cbc7562dfc8458fbefd714546e3c")
                );
                assert_eq!(pkey.curve, EDDSACurve::ED25519);
            }
            _ => panic!("Key should be parsed OKP key"),
        }
    }

    #[test]
    fn cbor_ed448() {
        let hex_data = hex!(
            "A4"         // Map - 4 elements
            "01 01"      //   1:   1,  ; kty: OKP key type
            "03 27"      //   3:  -8,  ; alg: EDDSA signature algorithm
            "20 07"      //  -1:   7,  ; crv: Ed448 curve
            "21 58 39   0c04658f79c3fd86c4b3d676057b76353126e9b905a7e204c07846c1a2ab3791b02fc5e9c6930345ea7bf8524b944220d4bd711c010c9b2a80" // -2:   x,  ; Y-coordinate
        );
        let val: Value = serde_cbor_2::from_slice(&hex_data).unwrap();
        let key = COSEKey::try_from(&val).unwrap();
        assert_eq!(key.type_, COSEAlgorithm::EDDSA);
        match key.key {
            COSEKeyType::EC_OKP(pkey) => {
                assert_eq!(
                    pkey.x.as_ref(),
                    hex!("0c04658f79c3fd86c4b3d676057b76353126e9b905a7e204c07846c1a2ab3791b02fc5e9c6930345ea7bf8524b944220d4bd711c010c9b2a80")
                );
                assert_eq!(pkey.curve, EDDSACurve::ED448);
            }
            _ => panic!("Key should be parsed OKP key"),
        }
    }
    */
}
