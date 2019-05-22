import * as hashJs from 'hash.js';

export function canonicalizeJwk(jwk: JsonWebKey & {kty: "RSA"}): JsonWebKey;
export function canonicalizeJwk(jwk: JsonWebKey & {kty: "EC"}): JsonWebKey;
export function canonicalizeJwk(jwk: JsonWebKey): JsonWebKey | undefined;

/**
 * Keep only required members
 * https://tools.ietf.org/html/rfc7638#section-3.1
 * @param jwk
 */
export function canonicalizeJwk(jwk: JsonWebKey): JsonWebKey | undefined {
  switch (jwk.kty) {
    case "RSA":
      return {
        e: jwk.e,
        kty: jwk.kty,
        n: jwk.n,
      };
    case "EC":
      return {
        crv: jwk.crv,
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y
      };
    default:
      return undefined;
  }
}

// NOTE: these strings are compatible with https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
type HashAlg = "SHA-256" | "SHA-512";

export function jwkThumbprint(jwk: JsonWebKey & {kty: "RSA"}, hashAlg: HashAlg): Uint8Array;
export function jwkThumbprint(jwk: JsonWebKey & {kty: "EC"}, hashAlg: HashAlg): Uint8Array;
export function jwkThumbprint(jwk: JsonWebKey, hashAlg: HashAlg): undefined;

/**
 * Calculate JWK Thumbprint
 *
 * https://tools.ietf.org/html/rfc7638#section-3.1
 * @param jwk
 * @param hashAlg
 */
export function jwkThumbprint(jwk: JsonWebKey, hashAlg: HashAlg): Uint8Array | undefined {
  // Canonicalize JWK
  const canonicalJwk = canonicalizeJwk(jwk);
  if (canonicalJwk === undefined) {
    return undefined;
  }

  // JSON string sorted by keys
  // (from: https://stackoverflow.com/a/16168003/2885946)
  const jsonStr = JSON.stringify(canonicalJwk, Object.keys(canonicalJwk));

  switch (hashAlg) {
    case "SHA-256":
      return new Uint8Array(hashJs.sha256().update(jsonStr).digest());
    case "SHA-512":
      return new Uint8Array(hashJs.sha512().update(jsonStr).digest());
    default:
      // Never call if the type is valid
      throw new Error(`Unexpected error: unknown algorithm: ${hashAlg}`);
  }
}
