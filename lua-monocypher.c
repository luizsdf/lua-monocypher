#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

#ifdef _WIN32
#include <bcrypt.h>
#define PRNG(buffer, size) BCryptGenRandom(NULL, buffer, size, \
                                           BCRYPT_USE_SYSTEM_PREFERRED_PRNG)
#elif defined(__linux__)
#include <sys/random.h>
#define PRNG(buffer, size) getrandom(buffer, size, 0);
#else
#define PRNG(buffer, size) arc4random_buf(buffer, size);
#endif

#ifndef luaL_newlib
#define luaL_newlib(L, l) (luaL_register(L, "monocypher", l))
#endif

static void *l_malloc(lua_State *L, size_t size)
{
    void *ptr = malloc(size);
    if (!ptr) luaL_error(L, "not enough memory");
    return ptr;
}

static int l_encrypt(lua_State *L)
{
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
                (const uint8_t *) ciphertext, (const uint8_t *) plaintext,
                text_size);

    lua_pushlstring(L, ciphertext, text_size + 40);
    lua_pushlstring(L, key, 32);
    free(ciphertext);
    if (free_key) free(key);
    return 2;
}

static int l_decrypt(lua_State *L)
{
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

static int l_blake2(lua_State *L)
{
    size_t message_size, key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    const char *key = luaL_optlstring(L, 2, NULL, &key_size);
    char digest[64];

    luaL_argcheck(L, key_size == 0 || key_size == 32, 2, "#key must be 32");
    crypto_blake2b_general((uint8_t *) digest, 64, (const uint8_t *) key,
                           key_size, (const uint8_t *) message, message_size);

    lua_pushlstring(L, digest, 64);
    return 1;
}

static int l_sha512(lua_State *L)
{
    size_t message_size, key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    const char *key = luaL_optlstring(L, 2, NULL, &key_size);
    char digest[64];

    luaL_argcheck(L, key_size == 0 || key_size == 32, 2, "#key must be 32");
    if (key) {
        crypto_hmac_sha512((uint8_t *) digest, (const uint8_t *) key, key_size,
                           (const uint8_t *) message, message_size);
    } else {
        crypto_sha512((uint8_t *) digest, (const uint8_t *) message,
                      message_size);
    }

    lua_pushlstring(L, digest, 64);
    return 1;
}

static int l_argon2(lua_State *L)
{
    size_t password_size, salt_size;
    const char *password = luaL_checklstring(L, 1, &password_size);
    char *salt = (char *) luaL_optlstring(L, 2, NULL, &salt_size);
    char free_salt = 0;
    uint32_t nb_blocks = luaL_optinteger(L, 3, 100000);
    uint32_t nb_iterations = luaL_optinteger(L, 4, 3);
    void *work_area;
    char digest[32];

    luaL_argcheck(L, salt_size == 0 || salt_size == 16, 2, "#salt must be 16");
    work_area = l_malloc(L, nb_blocks * 1024);
    if (!salt) {
        salt = (char *) l_malloc(L, 16);
        PRNG(salt, 16);
        free_salt = 1;
    }
    crypto_argon2i((uint8_t *) digest, 32, work_area, nb_blocks, nb_iterations,
                   (const uint8_t *) password, password_size,
                   (const uint8_t *) salt, 16);

    lua_pushlstring(L, digest, 32);
    lua_pushlstring(L, salt, 16);
    free(work_area);
    if (free_salt) free(salt);
    return 2;
}

static int l_exchange(lua_State *L)
{
    size_t their_public_key_size, your_secret_key_size;
    const char *their_public_key = luaL_optlstring(L, 1, NULL,
                                                   &their_public_key_size);
    char *your_secret_key = (char *) luaL_optlstring(L, 2, NULL,
                                                     &your_secret_key_size);
    char free_your_secret_key = 0;
    char your_public_key[32];
    char shared_key[32];
    const uint8_t zero[16] = { 0 };
    uint8_t their_x25519_public_key[32];

    luaL_argcheck(L, their_public_key_size == 0 || their_public_key_size == 32,
                  1, "#their_public_key must be 32");
    luaL_argcheck(L, your_secret_key_size == 0 || your_secret_key_size == 32,
                  2, "#your_secret_key must be 32");
    if (!your_secret_key) {
        your_secret_key = (char *) l_malloc(L, 32);
        PRNG(your_secret_key, 32);
        free_your_secret_key = 1;
    }
    if (their_public_key) {
        crypto_from_eddsa_public(their_x25519_public_key,
                                 (const uint8_t *) their_public_key);
        crypto_x25519((uint8_t *) shared_key, (const uint8_t *)
                      your_secret_key, their_x25519_public_key);
        crypto_hchacha20((uint8_t *) shared_key, (const uint8_t *) shared_key,
                         zero);
        lua_pushlstring(L, shared_key, 32);
    } else {
        lua_pushnil(L);
    }
    crypto_ed25519_public_key((uint8_t *) your_public_key,
                             (const uint8_t *) your_secret_key);

    lua_pushlstring(L, your_public_key, 32);
    lua_pushlstring(L, your_secret_key, 32);
    if (free_your_secret_key) free(your_secret_key);
    return 3;
}

static int l_sign(lua_State *L)
{
    size_t message_size, secret_key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    char *secret_key = (char *) luaL_optlstring(L, 2, NULL, &secret_key_size);
    char free_secret_key = 0;
    char signature[64];
    uint8_t digest[64];
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
    crypto_sha512(digest, (const uint8_t *) message, message_size);
    crypto_ed25519_sign((uint8_t *) signature, (const uint8_t *) secret_key,
                        (const uint8_t *) public_key, digest, 64);

    lua_pushlstring(L, signature, 64);
    lua_pushlstring(L, public_key, 32);
    lua_pushlstring(L, secret_key, 32);
    if (free_secret_key) free(secret_key);
    return 3;
}

static int l_check(lua_State *L)
{
    size_t message_size, signature_size, public_key_size;
    const char *message = luaL_checklstring(L, 1, &message_size);
    const char *signature = luaL_checklstring(L, 2, &signature_size);
    const char *public_key = luaL_checklstring(L, 3, &public_key_size);
    uint8_t digest[64];

    luaL_argcheck(L, signature_size == 64, 2, "#signature must be 64");
    luaL_argcheck(L, public_key_size == 32, 3, "#public_key must be 32");

    crypto_sha512(digest, (const uint8_t *) message, message_size);
    lua_pushboolean(L, crypto_ed25519_check((const uint8_t *) signature,
                    (const uint8_t *) public_key, digest, 64) == 0);
    return 1;
}

static int l_equal(lua_State *L)
{
    size_t i, a_size, b_size;
    const char *a = luaL_checklstring(L, 1, &a_size);
    const char *b = luaL_checklstring(L, 2, &b_size);
    int result = 0;

    if (a_size != b_size) lua_pushboolean(L, 0);
    for (i = 0; i < a_size; i++) result |= a[i] ^ b[i];
    lua_pushboolean(L, result == 0);
    return 1;
}

static int l_random(lua_State *L)
{
    size_t size = luaL_checkinteger(L, 1);
    char *buffer;

    buffer = l_malloc(L, size);
    PRNG(buffer, size);

    lua_pushlstring(L, buffer, size);
    free(buffer);
    return 1;
}

static const luaL_Reg l_monocypher[] = {
    { "encrypt", l_encrypt },
    { "decrypt", l_decrypt },
    { "blake2", l_blake2 },
    { "sha512", l_sha512 },
    { "argon2", l_argon2 },
    { "exchange", l_exchange },
    { "sign", l_sign },
    { "check", l_check },
    { "equal", l_equal },
    { "random", l_random },
    { NULL, NULL }
};

#ifdef __cplusplus
extern "C" {
#endif
int luaopen_monocypher(lua_State *L)
{
    luaL_newlib(L, l_monocypher);
    lua_pushstring(L, "Monocypher 3.1.3");
    lua_setfield(L, -2, "_VERSION");
    return 1;
}
#ifdef __cplusplus
}
#endif
