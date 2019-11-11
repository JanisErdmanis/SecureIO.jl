### I could limit myself to 65kb
# A tool for encrypting and decrypting data
using Nettle
using Serialization

function serializetostr(msg)
    io = IOBuffer()
    Serialization.serialize(io,msg)
    plaintext = String(take!(io))
    return plaintext
end


# function myencrypt(enc,text)
    

#     paddedtext = add_padding_PKCS5(Vector{UInt8}(text), 64)
#     @show paddedtext
#     ciphertext = encrypt(enc,paddedtext)
#     return ciphertext
# end

# function mydecrypt(dec,ciphertext)
#     deciphertext = decrypt(dec,ciphertext)
#     str = trim_padding_PKCS5(deciphertext)
#     return String(str)
# end

# key = 12902904902940
# key32 = hexdigest("sha256", "$key")[1:32]
# enc = Encryptor("AES256", key32)
# dec = Decryptor("AES256", key32)

# msg = "Thimessagesdsd\n"

# ciphertext = myencrypt(enc,msg)
# mydecrypt(dec,ciphertext)
