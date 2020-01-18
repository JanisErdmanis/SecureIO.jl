# A test for more abstract types

using SecureIO
using CryptoGroups
using CryptoSignatures
using Sockets

import SecureIO.Socket
import Serialization
Socket(socket::TCPSocket) = Socket(socket,Serialization.serialize,Serialization.deserialize) 

server = listen(2000)

@sync begin
    @async global serversocket = Socket(accept(server))
    global slavesocket = Socket(connect(2000))
end

key = "Password"

G = CryptoGroups.MODP160Group()
user = Signer(G)

stserver = SecureSocket(serversocket,key)
#serialize(stserver,user,1024)
serialize(stserver,user)

stslave = SecureSocket(slavesocket,key)

receiveduser = deserialize(stslave)
