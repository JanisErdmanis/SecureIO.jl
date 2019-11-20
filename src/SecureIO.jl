module SecureIO

### A temporary solution
import Sockets.TCPSocket
import Serialization
include("multiplexers.jl")

using Nettle

struct SecureTunnel <: IO
    socket::IO
    enc::Encryptor
    dec::Decryptor
end

function SecureTunnel(socket,key)
    
    key32 = hexdigest("sha256", "$key")[1:32]
    enc = Encryptor("AES256", key32)
    dec = Decryptor("AES256", key32)
    
    SecureTunnel(socket,enc,dec)
end

import Base.isopen
isopen(s::SecureTunnel) = isopen(s.socket)

import Base.close
close(s::SecureTunnel) = close(s.socket)


function addpadding(text::Vector{UInt8},size)
    # Only last two bytes are used to encode the padding boundary. That limits the possible size.
    @assert length(text) + 2 <= size <= 2^16
    
    endbytes = reinterpret(UInt8, Int16[length(text)])
    paddedtext = [text; UInt8[0 for i in 1:(size - length(text) - 2)]; endbytes] 
    
    return paddedtext
end

function trimpadding(text::Vector{UInt8})
    endbytes = text[end-1:end]
    n = reinterpret(Int16,endbytes)[1]
    return text[1:n]
end

function getstr(msg)
    io = IOBuffer()
    Serialization.serialize(io,msg)
    plaintext = take!(io)
    return plaintext
end


serialize(socket::TCPSocket,msg) = Serialization.serialize(socket,msg)
deserialize(socket::TCPSocket) = Serialization.deserialize(socket)


serialize(s::IOBuffer,data::Array) = write(s,data)
deserialize(s::IOBuffer) = take!(s)


function serialize(s::SecureTunnel,msg,size)
    plaintext = getstr(msg)

    if size - 2 < length(plaintext)
        error("Message with length $(length(plaintext)) does not fit in $size - 2 bytes")
    end
    
    #paddedtext = add_padding_PKCS5(Vector{UInt8}(plaintext), size)
    paddedtext = addpadding(plaintext, size)
    
    msgenc = encrypt(s.enc,paddedtext)
    serialize(s.socket,msgenc)
end

function serialize(s::SecureTunnel,msg)
    plaintext = getstr(msg)

    n = length(plaintext)

    if mod(n+2,16)==0
        size = n+2
    else
        size = (div(n+2,16) + 1)*16
    end

    paddedtext = addpadding(plaintext, size)
    msgenc = encrypt(s.enc,paddedtext)
    serialize(s.socket,msgenc)
end

function deserialize(s::SecureTunnel)
    ciphertext = deserialize(s.socket)
    deciphertext = decrypt(s.dec,ciphertext)
    
    #str = trim_padding_PKCS5(deciphertext)
    str = trimpadding(deciphertext)

    io = IOBuffer(str)
    msg = Serialization.deserialize(io)
    return msg
end

export SecureTunnel, serialize, deserialize

end # module
