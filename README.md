# lua-monocypher

A Lua wrapper for the [Monocypher](https://monocypher.org/) crypto library.

## API

### Authenticated encryption with XChaCha20 and Poly1305 ([RFC 8439](https://www.rfc-editor.org/rfc/rfc8439))

    lock(plain_text [, key]) => cipher_text, key
    unlock(cipher_text, key) => plain_text

    plain_text: string
    key: string (32 bytes), randomly generated when not provided
    cipher_text: nonce string (24 bytes) + string + MAC string (16 bytes)

### Hashing with BLAKE2b ([RFC 7693](https://www.rfc-editor.org/rfc/rfc7693))

    blake2b(message [, digest_size [, key]]) => digest

    message: string
    digest_size: number between 1 and 64 (the default is 64)
    key: string (32 bytes) for a PRF
    digest: string (digest_size bytes)

### Hashing with SHA-512 ([RFC 6234](https://www.rfc-editor.org/rfc/rfc6234))

    sha512(message) => digest

    message: string
    digest: string (64 bytes)

### Password hashing with Argon2i ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106))

    argon2i(password [, salt [, digest_size [, blocks [, iterations]]]]) => digest, salt

    password: string
    salt: string (16 bytes), randomly generated when not provided
    digest_size: number, either 32 or 64 (the default is 32)
    blocks: number of kilobytes allocated for the computation (the default is 100000)
    iterations: number (the default is 3)
    digest: string (digest_size bytes)

### Public key exchanges with X25519 ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748))

    x25519([their_public_key [, your_secret_key]]) => shared_secret, your_public_key, your_secret_key

    NOTE: shared_secret should be concatenated with the public keys and digested before used as a key.
    i.e. key = blake2b(shared_secret .. your_public_key .. their_public_key, 32)

    their_public_key: string (32 bytes)
    your_secret_key: string (32 bytes), randomly generated when not provided
    shared_secret: string (32 bytes) if their_public_key else nil
    your_public_key: string (32 bytes)

### Public key signatures ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032))

    sign(message [, secret_key]) => signature, public_key, secret_key
    ed25519_sign(message [, secret_key]) => signature, public_key, secret_key
    check(message, signature, public_key) => bool
    ed25519_check(message, signature, public_key) => bool

    message: string
    secret_key: string (32 bytes), randomly generated when not provided
    signature: string (64 bytes)
    public_key: string (32 bytes)

## License

This software is released under the Zero-Clause BSD (0BSD) license.
