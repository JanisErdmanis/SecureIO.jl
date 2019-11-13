module SecureIO

using Nettle
import Sockets.TCPSocket
import Serialization

function addpadding(text::Vector{UInt8},size)
    # Only tow last bytes are used to encode the padding boundary. That limits the possible size.
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

send(s::IO,data::Array) = write(s,data)
send(s::TCPSocket,data::Array) = Serialization.serialize(s,data)

function send(s::SecureTunnel,msg::Array) 
    msgenc = encrypt(s.enc,msg)
    send(s.socket,msgenc)
end

receive(s::IO) = take!(s)
receive(s::TCPSocket) = Serialization.deserialize(s)

function receive(s::SecureTunnel)
    msgenc = receive(s.socket)
    deciphertext = decrypt(s.dec,msgenc)
    return deciphertext
end

import Base.isopen
isopen(s::SecureTunnel) = isopen(s.socket)

import Base.close
close(s::SecureTunnel) = close(s.socket)

function getstr(msg)
    io = IOBuffer()
    Serialization.serialize(io,msg)
    plaintext = String(take!(io))
    return plaintext
end

function serialize(s::SecureTunnel,msg,size)
    plaintext = getstr(msg)

    if size - 2 < length(plaintext)
        error("Message with length $(length(plaintext)) does not fit in $size - 2 bytes")
    end
    
    #paddedtext = add_padding_PKCS5(Vector{UInt8}(plaintext), size)
    paddedtext = addpadding(Vector{UInt8}(plaintext), size)

    send(s,paddedtext)
end


function serialize(s::SecureTunnel,msg)
    plaintext = getstr(msg)

    n = length(plaintext)

    if mod(n+2,16)==0
        size = n+2
    else
        size = (div(n+2,16) + 1)*16
    end

    paddedtext = addpadding(Vector{UInt8}(plaintext), size)
    send(s,paddedtext)
end


function deserialize(s::SecureTunnel)
    deciphertext = receive(s)
    
    #str = trim_padding_PKCS5(deciphertext)
    str = trimpadding(deciphertext)

    io = IOBuffer(str)
    msg = Serialization.deserialize(io)
    return msg
end

export SecureTunnel, serialize, deserialize #, send, receive

end # module
