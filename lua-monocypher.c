#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

#ifdef _WIN32
#include <bcrypt.h>
#define PRNG(BUF, BUFLEN) BCryptGenRandom(NULL, BUF, BUFLEN, \
    BCRYPT_USE_SYSTEM_PREFERRED_PRNG)
#elif defined(__linux__)
#include <sys/random.h>
#define PRNG(BUF, BUFLEN) getrandom(BUF, BUFLEN, 0);
#else
#define PRNG(BUF, BUFLEN) arc4random_buf(BUF, BUFLEN);
#endif

#ifndef luaL_newlib
#define luaL_newlib(L, l) (luaL_register(L, "monocypher", l))
#endif

static void * l_malloc(lua_State *L, size_t size) {
    void *ptr = malloc(size);
    if (!ptr) luaL_error(L, "not enough memory");
    return ptr;
}

static int l_lock(lua_State *L) {
    size_t text_size, key_size;
    const char *plaintext = luaL_checklstring(L, 1, &text_size);
    char *key = (char *) luaL_optlstring(L, 2, NULL, &key_size);
    char free_key = 0;
    char *ciphertext;

    luaL_argcheck(L, key_size == 0 || key_size == 32, 2, "#key must be 32");
    ciphertext = (char *) l_malloc(L, text_size + 40);
    PRNG(ciphertext, 24);
    if (!key) {
        key = (char *) l_malloc(L, 32);
        PRNG(key, 32);
        free_key = 1;
    }
    crypto_lock((uint8_t *) ciphertext + 24 + text_size,
        (uint8_t *) ciphertext + 24, (const uint8_t *) key,
        (const uint8_t *) ciphertext, (const uint8_t *) plaintext, text_size);

    lua_pushlstring(L, ciphertext, text_size + 40);
    lua_pushlstring(L, key, 32);
    free(ciphertext);
    if (free_key) free(key);
    return 2;
}

static int l_unlock(lua_State *L) {
    size_t text_size, key_size;
    const char *ciphertext = luaL_checklstring(L, 1, &text_size);
    const char *key = luaL_checklstring(L, 2, &key_size);
    char *plaintext;

    luaL_argcheck(L, text_size >= 40, 1,
        "#ciphertext must be at least 40 (nonce + MAC)");
    luaL_argcheck(L, key_size == 32, 2, "#key must be 32");
    text_size -= 40;
    plaintext = (char *) l_malloc(L, text_size);
    if (crypto_unlock((uint8_t *) plaintext, (const uint8_t *) key,
        (const uint8_t *) ciphertext,
        (const uint8_t *) ciphertext + 24 + text_size,
        (const uint8_t *) ciphertext + 24, text_size) == -1) {
        free(plaintext);
        luaL_error(L, "bad ciphertext");
    }

    lua_pushlstring(L, plaintext, text_size);
    free(plaintext);
    return 1;
}

static int l_blake2b(lua_State *L) {
    size_t message_size, key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    size_t digest_size = luaL_optinteger(L, 2, 64);
    const char *key = luaL_optlstring(L, 3, NULL, &key_size);
    char *digest;

    luaL_argcheck(L, digest_size >= 1 && digest_size <= 64, 2,
        "digest_size must be between 1 and 64");
    luaL_argcheck(L, key_size == 0 || key_size == 32, 3, "#key must be 32");
    digest = (char *) l_malloc(L, digest_size);
    crypto_blake2b_general((uint8_t *) digest, digest_size,
        (const uint8_t *) key, key_size, (const uint8_t *) message,
        message_size);

    lua_pushlstring(L, digest, digest_size);
    free(digest);
    return 1;
}

static int l_sha512(lua_State *L) {
    size_t message_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    char digest[64];

    crypto_sha512((uint8_t *) digest, (const uint8_t *) message, message_size);

    lua_pushlstring(L, digest, 64);
    return 1;
}

static int l_argon2i(lua_State *L) {
    size_t password_size, salt_size;
    const char *password = luaL_checklstring(L, 1, &password_size);
    char *salt = (char *) luaL_optlstring(L, 2, NULL, &salt_size);
    char free_salt = 0;
    uint32_t digest_size = luaL_optinteger(L, 3, 32);
    uint32_t nb_blocks = luaL_optinteger(L, 4, 100000);
    uint32_t nb_iterations = luaL_optinteger(L, 5, 3);
    char *digest;
    void *work_area;

    luaL_argcheck(L, salt_size == 0 || salt_size == 16, 2,
        "#salt must be 16");
    luaL_argcheck(L, digest_size == 32 || digest_size == 64, 3,
        "digest_size must be either 32 or 64");
    work_area = l_malloc(L, nb_blocks * 1024);
    digest = (char *) l_malloc(L, digest_size);
    if (!salt) {
        salt = (char *) l_malloc(L, 16);
        PRNG(salt, 16);
        free_salt = 1;
    }
    crypto_argon2i((uint8_t *) digest, digest_size, work_area, nb_blocks,
        nb_iterations, (const uint8_t *) password, password_size,
        (const uint8_t *) salt, 16);

    lua_pushlstring(L, digest, digest_size);
    lua_pushlstring(L, salt, 16);
    free(work_area);
    free(digest);
    if (free_salt) free(salt);
    return 2;
}

static int l_x25519(lua_State *L) {
    size_t their_public_key_size, your_secret_key_size;
    const char *their_public_key = luaL_optlstring(L, 1, NULL,
        &their_public_key_size);
    char *your_secret_key = (char *) luaL_optlstring(L, 2, NULL,
        &your_secret_key_size);
    char free_your_secret_key = 0;
    char your_public_key[32];
    char shared_secret[32];

    luaL_argcheck(L, their_public_key_size == 0 || their_public_key_size == 32,
        1, "#their_public_key must be 32");
    luaL_argcheck(L, your_secret_key_size == 0 || your_secret_key_size == 32, 2,
        "#your_secret_key must be 32");
    if (!your_secret_key) {
        your_secret_key = (char *) l_malloc(L, 32);
        PRNG(your_secret_key, 32);
        free_your_secret_key = 1;
    }
    if (their_public_key) {
        crypto_x25519((uint8_t *) shared_secret, (const uint8_t *)
            your_secret_key, (const uint8_t *) their_public_key);
        lua_pushlstring(L, shared_secret, 32);
    } else {
        lua_pushnil(L);
    }
    crypto_x25519_public_key((uint8_t *) your_public_key, (const uint8_t *)
        your_secret_key);

    lua_pushlstring(L, your_public_key, 32);
    lua_pushlstring(L, your_secret_key, 32);
    if (free_your_secret_key) free(your_secret_key);
    return 3;
}

static int l_sign(lua_State *L) {
    size_t message_size, secret_key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    char *secret_key = (char *) luaL_optlstring(L, 2, NULL, &secret_key_size);
    char free_secret_key = 0;
    char signature[64];
    char public_key[32];

    luaL_argcheck(L, secret_key_size == 0 || secret_key_size == 32, 2,
        "#secret_key must be 32");
    if (!secret_key) {
        secret_key = (char *) l_malloc(L, 32);
        PRNG(secret_key, 32);
        free_secret_key = 1;
    }
    crypto_sign_public_key((uint8_t *) public_key,
        (const uint8_t *) secret_key);
    crypto_sign((uint8_t *) signature, (const uint8_t *) secret_key,
        (const uint8_t *) public_key, (const uint8_t *) message, message_size);

    lua_pushlstring(L, signature, 64);
    lua_pushlstring(L, public_key, 32);
    lua_pushlstring(L, secret_key, 32);
    if (free_secret_key) free(secret_key);
    return 3;
}

static int l_check(lua_State *L) {
    size_t message_size, signature_size, public_key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    const char *signature = luaL_checklstring(L, 2, &signature_size);
    const char *public_key = luaL_checklstring(L, 3, &public_key_size);

    luaL_argcheck(L, signature_size == 64, 2, "#signature must be 64");
    luaL_argcheck(L, public_key_size == 32, 3, "#public_key must be 32");

    lua_pushboolean(L, crypto_check((const uint8_t *) signature,
        (const uint8_t *) public_key, (const uint8_t *) message,
        message_size) == 0);
    return 1;
}

static int l_ed25519_sign(lua_State *L) {
    size_t message_size, secret_key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    char *secret_key = (char *) luaL_optlstring(L, 2, NULL, &secret_key_size);
    char free_secret_key = 0;
    char signature[64];
    char public_key[32];

    luaL_argcheck(L, secret_key_size == 0 || secret_key_size == 32, 2,
        "#secret_key must be 32");
    if (!secret_key) {
        secret_key = (char *) l_malloc(L, 32);
        PRNG(secret_key, 32);
        free_secret_key = 1;
    }
    crypto_ed25519_public_key((uint8_t *) public_key,
        (const uint8_t *) secret_key);
    crypto_ed25519_sign((uint8_t *) signature, (const uint8_t *) secret_key,
        (const uint8_t *) public_key, (const uint8_t *) message, message_size);

    lua_pushlstring(L, signature, 64);
    lua_pushlstring(L, public_key, 32);
    lua_pushlstring(L, secret_key, 32);
    if (free_secret_key) free(secret_key);
    return 3;
}

static int l_ed25519_check(lua_State *L) {
    size_t message_size, signature_size, public_key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    const char *signature = luaL_checklstring(L, 2, &signature_size);
    const char *public_key = luaL_checklstring(L, 3, &public_key_size);

    luaL_argcheck(L, signature_size == 64, 2, "#signature must be 64");
    luaL_argcheck(L, public_key_size == 32, 3, "#public_key must be 32");

    lua_pushboolean(L, crypto_ed25519_check((const uint8_t *) signature,
        (const uint8_t *) public_key, (const uint8_t *) message,
        message_size) == 0);
    return 1;
}

static const luaL_Reg l_monocypher[] = {
    { "lock", l_lock },
    { "unlock", l_unlock },
    { "blake2b", l_blake2b },
    { "sha512", l_sha512 },
    { "argon2i", l_argon2i },
    { "x25519", l_x25519 },
    { "sign", l_sign },
    { "check", l_check },
    { "ed25519_sign", l_ed25519_sign },
    { "ed25519_check", l_ed25519_check },
    { NULL, NULL }
};

#ifdef __cplusplus
extern "C" {
#endif
int luaopen_monocypher(lua_State *L) {
    luaL_newlib(L, l_monocypher);
    lua_pushstring(L, "Monocypher 3.1.3");
    lua_setfield(L, -2, "_VERSION");
    return 1;
}
#ifdef __cplusplus
}
#endif
