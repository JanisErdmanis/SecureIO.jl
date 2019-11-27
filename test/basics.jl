using SecureIO
using Sockets
using Test

io = IOBuffer()

key = "Password"
st = SecureSerializer(io,key)

msg = ("Hello","World")
serialize(st,msg,32)
@test msg==deserialize(st) 

# Inception/Onion

io = IOBuffer()

key1 = "Password1"
st1 = SecureSerializer(io,key1)

key2 = "Password2"
st2 = SecureSerializer(st1,key2)

msg = ("Hello","World")
serialize(st2,msg,64)
@test msg==deserialize(st2) 

# Checking if TCP/IP sockets works

server = listen(2000)

@sync begin
    @async global serversocket = accept(server)
    global slavesocket = connect(2000)
end

key = "Password"

msg = ("Hello","World")

stserver = SecureSerializer(serversocket,key)
serialize(stserver,msg,64)

stslave = SecureSerializer(slavesocket,key)
@test msg==deserialize(stslave)

@test isopen(stslave)==true
close(stslave)
@test isopen(stslave)==false

close(server)
