using SecureIO
using Multiplexers
using Sockets
using Serialization

key = 12434434
N = 2

@sync begin
    @async let
        routers = listen(2001)
        try
            @show "Router"
            serversocket = accept(routers)
            secureserversocket = SecureSocket(serversocket,key)
            
            mux = Multiplexer(secureserversocket,N)

            susersockets = []
            for i in 1:N
                push!(susersockets,SecureSocket(mux.lines[i],key))
            end

            for i in 1:N
                serialize(susersockets[i],"A secure message from the router")

                @show deserialize(susersockets[i])
                
                @async serialize(susersockets[i],"Hello from router")
                @show deserialize(susersockets[i])
            end
            
            close(mux)
        finally
            close(routers)
        end
    end

    @async let
        servers = listen(2000)
        try 
            @show "Server"
            routersocket = connect(2001)
            secureroutersocket = SecureSocket(routersocket,key)
            
            usersockets = IO[]

            while length(usersockets)<N
                socket = accept(servers)
                push!(usersockets,SecureSocket(socket,key))
            end

            mux = Multiplexer(secureroutersocket,usersockets)
            wait(mux)
        finally
            close(servers)
        end
    end

    @async let
        @show "User 1"
        usersocket = connect(2000)
        securesocket = SecureSocket(usersocket,key)

        sroutersocket = SecureSocket(securesocket,key)
        @show deserialize(sroutersocket)
        serialize(sroutersocket,"A scuere msg from user 1")

        @async serialize(sroutersocket,"Hello user 1")
        @show deserialize(sroutersocket)
    end

    @async let
        @show "User 2"
        usersocket = connect(2000)
        securesocket = SecureSocket(usersocket,key)
        
        sroutersocket = SecureSocket(securesocket,key)
        @show deserialize(sroutersocket)
        serialize(sroutersocket,"A scuere msg from user 2")

        @async serialize(sroutersocket,"Hello user 2")
        @show deserialize(sroutersocket)
    end
end



