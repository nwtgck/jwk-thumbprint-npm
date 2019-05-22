import * as hashJs from 'hash.js';
import { Base64 } from "js-base64"

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
export function jwkThumbprint(jwk: JsonWebKey, hashAlg: HashAlg): Uint8Array | undefined;

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

export function jwkThumbprintBase64url(jwk: JsonWebKey & {kty: "RSA"}, hashAlg: HashAlg): string;
export function jwkThumbprintBase64url(jwk: JsonWebKey & {kty: "EC"}, hashAlg: HashAlg): string;
export function jwkThumbprintBase64url(jwk: JsonWebKey, hashAlg: HashAlg): string | undefined;

/**
 * Calculate JWK Thumbprint as base64url
 *
 * https://tools.ietf.org/html/rfc7638#section-3.1
 * @param jwk
 * @param hashAlg
 */
export function jwkThumbprintBase64url(jwk: JsonWebKey, hashAlg: HashAlg): string | undefined {
  // Calculate thumbprint
  const thumbprint: Uint8Array | undefined = jwkThumbprint(jwk, hashAlg);
  if (thumbprint === undefined) {
    return undefined;
  }

  // (from: https://paulownia.hatenablog.com/entry/2019/02/07/201320)
  const binStr = Array.from(thumbprint).map(b => String.fromCharCode(b)).join("");
  // (from:  https://github.com/brianloveswords/base64url/blob/20117777e233fc86ac1286ccbc998bd6c923f149/src/base64url.ts#L25-L27)
  return Base64.btoa(binStr)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
