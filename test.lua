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
    local ciphertext, key = monocypher.encrypt(text)
    local plaintext = monocypher.decrypt(ciphertext, key)
    assert(plaintext == text)
    print("OK")
end

do
    io.write("Hashing with BLAKE2...")
    local hash = monocypher.blake2(text)
    assert(tohex(hash) == "0ec168f3f6399913010508be19ab89f08f2d94f836db1467" ..
                          "adc6f3253fe49544e8e12cc6066ee9f78d18aa5667afa466" ..
                          "542db5a0d0de92d73784bca37bcc62e8")
    print("OK")
end

do
    io.write("Hashing with SHA-512...")
    local hash = monocypher.sha512(text)
    assert(tohex(hash) == "38534e0a9ddbbdf8be8d92f4fa33ea444a9be21782623a3a" ..
                          "1fc173138ceb65d8efeb03436abe2bed6412f395f2446afe" ..
                          "fa92397a247aa117f5de7515b1902e5e")
    print("OK")
end

do
    io.write("Password hashing...")
    local hash = monocypher.argon2("Passw0rd!", "Never gonna give")
    assert(tohex(hash) == "d029f480f1f33f626877e13256c5006e513719850725dc72" ..
                          "7d253c20647f220f11b8df78fe44b5f62f1ab9ceaae2093f" ..
                          "bc9200a45d377a537a0ca3834de92c0b")
    print("OK")
end

do
    io.write("Public key exchanges...")
    local _, alice_public_key, alice_secret_key = monocypher.exchange()
    local shared_key, bob_public_key = monocypher.exchange(alice_public_key)
    assert(monocypher.exchange(bob_public_key, alice_secret_key) == shared_key)
    print("OK")
end

do
    io.write("Public key signatures...")
    local signature, public_key = monocypher.sign(text)
    assert(monocypher.check(text, signature, public_key))
    print("OK")
end
