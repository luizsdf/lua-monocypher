# lua-monocypher

An **easier** to use Lua crypto library.

## Authenticated encryption with XChaCha20 and Poly1305 ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439))

    encrypt(plaintext [, key]) => ciphertext, key
    decrypt(ciphertext, key) => plaintext

    plaintext: string
    key: string (32 bytes), randomly generated if not provided
    ciphertext: nonce string (24 bytes) + string + MAC string (16 bytes)

## Hashing with BLAKE2 ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693))

    blake2(message [, key]) => digest

    message: string
    key: string (32 bytes) for a MAC
    digest: string (64 bytes)

## Hashing with SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234))

    sha512(message [, key]) => digest

    message: string
    key: string (32 bytes) for a MAC
    digest: string (64 bytes)

## Password hashing with Argon2 ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106))

    argon2(password [, salt [, blocks [, iterations]]]) => digest, salt

    password: string
    salt: string (16 bytes), randomly generated if not provided
    blocks: number of kilobytes allocated for the computation (the default is 100000)
    iterations: number (the default is 3)
    digest: string (32 bytes)

## Public key exchanges with X25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748))

    exchange([their_public_key [, your_secret_key]]) => shared_key, your_public_key, your_secret_key

    their_public_key: string (32 bytes)
    your_secret_key: string (32 bytes), randomly generated if not provided
    your_public_key: string (32 bytes)
    shared_key: string (32 bytes) if their_public_key else nil

## Public key signatures with Ed25519ph ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032))

    sign(message [, secret_key]) => signature, public_key, secret_key
    check(message, signature, public_key) => bool

    message: string
    secret_key: string (32 bytes), randomly generated if not provided
    public_key: string (32 bytes)
    signature: string (64 bytes)

## Constant-time comparisons

    equal(a, b) => bool

    a: string
    b: string

## OS PRNG

    random(size) => buffer

    size: number
    buffer: string (size bytes)

## License

This software is released under the Zero-Clause BSD (0BSD) license.
