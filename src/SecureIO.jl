module SecureIO

using Nettle
import Sockets.TCPSocket
import Serialization

struct SecureTunnel <: IO
    socket::IO
    enc::Encryptor
    dec::Decryptor
end

function SecureTunnel(socket,key)
    
    key32 = hexdigest("sha256", key)[1:32]
    enc = Encryptor("AES256", key32)
    dec = Decryptor("AES256", key32)
    
    SecureTunnel(socket,enc,dec)
end

send(s::TCPSocket,data::Array) = println(s,String(data))

function send(s::SecureTunnel,msg::Array) 
    msgenc = encrypt(s.enc,msg)
    write(s.socket,msgenc)
end

receive(s::TCPSocket) = Vector{UInt8}(readline(s, keep=true))[1:end-1]

function receive(s::SecureTunnel)
    msgenc = take!(s.socket)
    deciphertext = decrypt(s.dec,msgenc)
    
    return deciphertext
end

function serialize(s::SecureTunnel,msg,size)
    io = IOBuffer()
    serialize(io,msg)
    plaintext = String(take!(io))
    
    if size<length(plaintext)
        error("Message does not fit in $size bytes")
    end
    
    paddedtext = add_padding_PKCS5(Vector{UInt8}(plaintext), size)

    send(s,paddedtext)
end

function deserialize(s::SecureTunnel)
    deciphertext = receive(s)
    
    str = trim_padding_PKCS5(deciphertext)

    io = IOBuffer(str)
    msg = deserialize(io)
    return msg
end

export SecureTunnel, serialize, deserialize #, send, receive

end # module
