serialize(socket::TCPSocket,msg) = Serialization.serialize(socket,msg)
deserialize(socket::TCPSocket) = Serialization.deserialize(socket)

struct Line <: IO
    socket::IO
    ch::Channel
    n
end

Line(socket,n) = Line(socket,Channel(),n)

serialize(line::Line,msg) = serialize(line.socket,(line.n,msg))
deserialize(line::Line) = take!(line.ch)

"""
Takes multiple input lines and routes them to a single line.
"""
function route(lines::Vector{Line},socket)
    while true
        data = deserialize(socket)
        if data==:Terminate
            serialize(socket,:Terminate)
            return
        else
            n,msg = data
            put!(lines[n].ch,msg)
        end
    end
end

"""
A function which one uses to forward forward traffic from multiple sockets into one socket by multiplexing.
"""
function route(ios::Vector{IO},socket)
    lines = [Line(socket,i) for i in 1:length(ios)]
    task = @async route(lines,socket)
    
    for (line,io) in zip(lines,ios)
        @async while true
            msg = deserialize(line)
            serialize(io,msg)
        end
        
        @async while true
            msg = deserialize(io)
            serialize(line,msg)
        end
    end

    wait(task)
end


