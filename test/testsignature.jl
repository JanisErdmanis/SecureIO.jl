using SecureIO
using CryptoGroups
using CryptoSignatures
using Sockets

server = listen(2000)

@sync begin
    @async global serversocket = accept(server)
    global slavesocket = connect(2000)
end

key = "Password"

G = CryptoGroups.MODP160Group()
user = Signer(G)

stserver = SecureTunnel(serversocket,key)
serialize(stserver,user,1024)

stslave = SecureTunnel(slavesocket,key)

receiveduser = deserialize(stslave)
