local monocypher = require("monocypher")

io.output():setvbuf("no")

print(monocypher._VERSION)

local text = [[
Never gonna give you up
Never gonna let you down
Never gonna run around and desert you
Never gonna make you cry
Never gonna say goodbye
Never gonna tell a lie and hurt you
]]

local function tohex(str)
    return (str:gsub('.', function (c)
        return string.format("%02x", c:byte())
    end))
end

do
    io.write("Authenticated encryption...")
    local cipher_text, key = monocypher.lock(text)
    local plain_text = monocypher.unlock(cipher_text, key)
    assert(plain_text == text)
    print("OK")
end

do
    io.write("Hashing with BLAKE2...")
    local hash = monocypher.blake2b(text)
    assert(tohex(hash) == "0ec168f3f6399913010508be19ab89f08f2d94f836db1467a" ..
        "dc6f3253fe49544e8e12cc6066ee9f78d18aa5667afa466542db5a0d0de92d73784" ..
        "bca37bcc62e8")
    print("OK")
end

do
    io.write("Hashing with SHA-512...")
    local hash = monocypher.sha512(text)
    assert(tohex(hash) == "38534e0a9ddbbdf8be8d92f4fa33ea444a9be21782623a3a1" ..
        "fc173138ceb65d8efeb03436abe2bed6412f395f2446afefa92397a247aa117f5de" ..
        "7515b1902e5e")
    print("OK")
end

do
    io.write("Password hashing...")
    local hash = monocypher.argon2("Passw0rd!", "Never gonna give")
    assert(tohex(hash) == "f7b146d75eda98e94de97e06140716be6b8a1f51324e3da76" ..
        "f42e0e795618568")
    print("OK")
end

do
    io.write("Public key exchanges...")
    local _, alice_public_key, alice_secret_key = monocypher.x25519()
    local shared_secret, bob_public_key = monocypher.x25519(alice_public_key)
    assert(monocypher.x25519(bob_public_key, alice_secret_key) == shared_secret)
    print("OK")
end

do
    io.write("Public key signatures...")
    local signature, public_key = monocypher.eddsa_sign(text)
    assert(monocypher.eddsa_check(text, signature, public_key))
    signature, public_key = monocypher.ed25519_sign(text)
    assert(monocypher.ed25519_check(text, signature, public_key))
    print("OK")
end
