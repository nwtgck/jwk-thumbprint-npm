# jwk-thumbprint
![npm](https://img.shields.io/npm/v/jwk-thumbprint.svg) [![CircleCI](https://circleci.com/gh/nwtgck/jwk-thumbprint-npm.svg?style=shield)](https://circleci.com/gh/nwtgck/jwk-thumbprint-npm)

JWK Thumbprint for JavaScript/TypeScript on both Web Browser and Node.js

## Installation

```bash
npm i -S jwk-thumbprint
```

## Usage

Here is an usage to reproduce the example in [RFC7638 3.1](<https://tools.ietf.org/html/rfc7638#section-3.1>).

```ts
// TypeScript
// (Remove types to use it in JavaScript)

import {jwkThumbprint} from 'jwk-thumbprint';

const myJwk: JsonWebKey & {kty: 'RSA', kid: string} = {
  kty: 'RSA',
  n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  e: 'AQAB',
  alg: 'RS256',
  kid: '2011-04-29',
};

console.log(jwkThumbprint(myJwk, 'SHA-256'));
// => new Uint8Array([55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123])
```

### Thumbprints in number array, hex and base64url encodings

First, import the following.

```ts
import {jwkThumbprintByEncoding} from 'jwk-thumbprint';
```

You can get different encodings by `'number'`, `'hex'`, `'base64url'` or `'uint8array'` in **type-safe way**. The return types are properly typed by the encodings.

```ts
const thumbprint: number[] = jwkThumbprintByEncoding(jwk, "SHA-256", 'numbers');
console.log(thumbprint)
// => 55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123]
```

```ts
const thumbprint: string = jwkThumbprintByEncoding(jwk, "SHA-256", 'hex');
console.log(thumbprint)
// => 3736cbb1787cb8309c77ee8c3705c5e16ffb9e859715901f1e4c59b11182f57b
```


```ts
const thumbprint: string = jwkThumbprintByEncoding(jwk, "SHA-256", 'base64url');
console.log(thumbprint)
// => NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
```

```ts
const thumbprint: Uint8Array = jwkThumbprintByEncoding(jwk, "SHA-256", 'uint8array');
console.log(thumbprint)
// => new Uint8Array([55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123])
```
