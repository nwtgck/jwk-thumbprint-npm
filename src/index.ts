import * as hashJs from 'hash.js';
import { Base64 } from "js-base64"

export function canonicalizeJwk(jwk: JsonWebKey & {kty: "RSA"}): JsonWebKey;
export function canonicalizeJwk(jwk: JsonWebKey & {kty: "EC"}): JsonWebKey;
export function canonicalizeJwk(jwk: JsonWebKey & {kty: "oct"}): JsonWebKey;
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
    case "oct":
      return {
        k: jwk.k,
        kty: jwk.kty,
      };
    default:
      return undefined;
  }
}

// NOTE: these strings are compatible with https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
type HashAlg = "SHA-256" | "SHA-512";

type Encodings = 'numbers' | 'hex' | 'uint8array' | 'base64url';

type EcType = {
  numbers: number[],
  hex: string;
  uint8array: Uint8Array,
  base64url: string
}

export function jwkThumbprintByEncoding<Ec extends Encodings>(jwk: JsonWebKey & {kty: "RSA" | "EC" | "oct"}, hashAlg: HashAlg, ec: Ec): EcType[Ec];
export function jwkThumbprintByEncoding<Ec extends Encodings>(jwk: JsonWebKey, hashAlg: HashAlg, ec: Ec): EcType[Ec] | undefined;

/**
 * Calculate JWK Thumbprint by encoding
 *
 * https://tools.ietf.org/html/rfc7638#section-3.1
 * @param jwk
 * @param hashAlg
 * @param ec
 */
export function jwkThumbprintByEncoding<Ec extends Encodings>(jwk: JsonWebKey, hashAlg: HashAlg, ec: Ec): EcType[Ec] | undefined {
  // Canonicalize JWK
  const canonicalJwk = canonicalizeJwk(jwk);
  if (canonicalJwk === undefined) {
    return undefined;
  }

  // JSON string sorted by keys
  // (from: https://stackoverflow.com/a/16168003/2885946)
  const jsonStr = JSON.stringify(canonicalJwk, Object.keys(canonicalJwk).sort());

  const digest: Sha256 | Sha512 = (() => {
    switch (hashAlg) {
      case "SHA-256":
        return hashJs.sha256().update(jsonStr);
      case "SHA-512":
        return hashJs.sha512().update(jsonStr);
      default:
        // Never call if the type is valid
        throw new Error(`Unexpected error: unknown algorithm: ${hashAlg}`);
    }
  })();

  switch (ec) {
    case 'numbers':
      return digest.digest();
    case 'hex':
      return digest.digest('hex');
    case "uint8array":
      return new Uint8Array(digest.digest());
    case 'base64url':
      // (from: https://paulownia.hatenablog.com/entry/2019/02/07/201320)
      const binStr = digest.digest().map(b => String.fromCharCode(b)).join("");
      // (from:  https://github.com/brianloveswords/base64url/blob/20117777e233fc86ac1286ccbc998bd6c923f149/src/base64url.ts#L25-L27)
      return Base64.btoa(binStr)
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
    default:
      // Never call if the type is valid
      throw new Error(`Unexpected encoding: ${ec}`);
  }
}

export function jwkThumbprint<Ec extends Encodings>(jwk: JsonWebKey & {kty: "RSA" | "EC" | "oct"}, hashAlg: HashAlg): Uint8Array;
export function jwkThumbprint<Ec extends Encodings>(jwk: JsonWebKey, hashAlg: HashAlg): Uint8Array | undefined;

/**
 * Calculate JWK Thumbprint
 *
 * https://tools.ietf.org/html/rfc7638#section-3.1
 * @param jwk
 * @param hashAlg
 */
export function jwkThumbprint(jwk: JsonWebKey, hashAlg: HashAlg): Uint8Array | undefined {
  return jwkThumbprintByEncoding(jwk, hashAlg, 'uint8array');
}
