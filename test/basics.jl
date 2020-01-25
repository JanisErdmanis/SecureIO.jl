using SecureIO
using Sockets
using Test
using Serialization


#import SecureIO.Socket
#Socket(socket::IOBuffer) = Socket(socket,write,take!)

# I  need to find why write and take! does not work for the socket
#import Serialization
#Socket(socket::TCPSocket) = Socket(socket,Serialization.serialize,Serialization.deserialize) 

#io = Socket(IOBuffer())
io = IOBuffer()

key = "Password"
st = SecureSocket(io,key,size=32)

msg = ("Hello","World")
serialize(st,msg)
@test msg==deserialize(st) 

# Inception/Onion

io = IOBuffer()

key1 = "Password1"
st1 = SecureSocket(io,key1)

key2 = "Password2"
st2 = SecureSocket(st1,key2,size=64)

msg = ("Hello","World")
serialize(st2,msg)
@test msg==deserialize(st2) 

# Checking if TCP/IP sockets works

server = listen(2000)

@sync begin
    @async global serversocket = accept(server)
    global slavesocket = connect(2000)
end

key = "Password"

msg = ("Hello","World")

stserver = SecureSocket(serversocket,key,size=64)
serialize(stserver,msg)

stslave = SecureSocket(slavesocket,key)
@test msg==deserialize(stslave)

# Let's now test asyncchronicity

@async serialize(stserver,msg)
@async serialize(stslave,msg)

@test deserialize(stserver)==msg
@test deserialize(stslave)==msg

# Closing

@test isopen(stslave)==true
close(stslave)
@test isopen(stslave)==false

close(server)
