module SecureIO

using Nettle

struct SecureSocket <: IO
    socket::IO
    size::Union{Integer,Nothing}
    ch::Channel{UInt8}
    enc::Encryptor
    dec::Decryptor
end

function SecureSocket(socket::IO,key;size=nothing)
    size!=nothing && @assert mod(size,16)==0

    key32 = hexdigest("sha256", "$key")[1:32]
    enc = Encryptor("AES256", key32)
    dec = Decryptor("AES256", key32)
    
    SecureSocket(socket,size,Channel{UInt8}(Inf),enc,dec)
end

import Base.isopen
isopen(s::SecureSocket) = isopen(s.socket)

import Base.close
close(s::SecureSocket) = close(s.socket)

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

function stack(io::IO,msg::Vector{UInt8})
    frontbytes = reinterpret(UInt8,Int16[length(msg)])
    item = UInt8[frontbytes...,msg...]
    write(io,item)
end

function unstack(io::IO)
    sizebytes = [read(io,UInt8),read(io,UInt8)]
    size = reinterpret(Int16,sizebytes)[1]
    
    msg = UInt8[]
    for i in 1:size
        push!(msg,read(io,UInt8))
    end
    return msg
end

function unstack(io::IOBuffer)
    bytes = take!(io)
    size = reinterpret(Int16,bytes[1:2])[1]
    msg = bytes[3:size+2]
    if length(bytes)>size+2
        write(io,bytes[size+3:end])
    end
    return msg
end

import Base.write
function _write_fixed(s::SecureSocket,plaintext::Vector{UInt8},size)
    if size - 2 < length(plaintext)
        error("Message with length $(length(plaintext)) does not fit in $size - 2 bytes")
    end
    
    #paddedtext = add_padding_PKCS5(Vector{UInt8}(plaintext), size)
    paddedtext = addpadding(plaintext, size)
    
    msgenc = encrypt(s.enc,paddedtext)
    stack(s.socket,msgenc)
end

function _write_elastic(s::SecureSocket,plaintext::Vector{UInt8})
    n = length(plaintext)

    if mod(n+2,16)==0
        size = n+2
    else
        size = (div(n+2,16) + 1)*16
    end

    paddedtext = addpadding(plaintext, size)
    msgenc = encrypt(s.enc,paddedtext)
    stack(s.socket,msgenc)
end

function _write(s::SecureSocket,msg::Vector{UInt8})
    if s.size==nothing
        _write_elastic(s,msg)
    else
        _write_fixed(s,msg,s.size)
    end
end

_write(s::SecureSocket,msg::UInt8) = _write(s,UInt8[msg])
_write(s::SecureSocket,msg::String) = _write(s,Vector{UInt8}(msg))

write(s::SecureSocket,msg::UInt8) = _write(s,msg)
write(s::SecureSocket,msg::String) = _write(s,msg)
write(s::SecureSocket,msg::Vector{UInt8}) = _write(s,msg)

function getbytes(s::SecureSocket)
    ciphertext = unstack(s.socket) ### If s.socket is a buffer. 

    deciphertext = decrypt(s.dec,ciphertext)
    
    #str = trim_padding_PKCS5(deciphertext)
    msg = trimpadding(deciphertext)

    if typeof(msg)==UInt8
        return msg
    else
        return take!(IOBuffer(msg))
    end
end

import Base.read
function read(s::SecureSocket,x::Type{UInt8})
    if isready(s.ch)==false
        bytes = getbytes(s)
        if typeof(bytes)==UInt8
            put!(s.ch,bytes)
        else
            for byte in bytes
                put!(s.ch,byte)
            end
        end
    end

    return take!(s.ch)
end

export SecureSocket, read, write

end # module
