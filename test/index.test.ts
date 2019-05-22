import {jwkThumbprint, jwkThumbprintBase64url} from '../src';
import * as assert from 'power-assert';

describe('jwk-thumbprint', () => {
  it('should return the same thumbprint as an example in RFC7638', () => {
    // (from: https://tools.ietf.org/html/rfc7638#section-3.1)
    const jwk: JsonWebKey & {kty: "RSA", kid: string} = {
      "kty": "RSA",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB",
      "alg": "RS256",
      "kid": "2011-04-29"
    };
    {
      const actual = jwkThumbprint(jwk, "SHA-256");
      // NOTE: This expectation is also on https://tools.ietf.org/html/rfc7638#section-3.1
      const expect = new Uint8Array( [
        55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197,
        225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130,
        245, 123
      ]);
      assert.deepStrictEqual(actual, expect);
    }

    {
      const actual = jwkThumbprintBase64url(jwk, "SHA-256");
      // NOTE: This expectation is also on https://tools.ietf.org/html/rfc7638#section-3.1
      const expect = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
      assert.deepStrictEqual(actual, expect);
    }
  });
});
