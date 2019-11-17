# using Serialization
# import Serialization.serialize
# import Serialization.deserialize

serialize(socket::TCPSocket,msg) = Serialization.serialize(socket,msg)
deserialize(socket::TCPSocket) = Serialization.deserialize(socket)

struct Line <: IO
    socket::IO
    ch::Channel
    n
end

Line(socket,n) = Line(socket,Channel(),n)

function serialize(line::Line,msg) 
    #@show msg, typeof(line.socket)
    serialize(line.socket,(line.n,msg))
    #@show "Did you pass this?"
end

deserialize(line::Line) = take!(line.ch)

#import Sockets.connect
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
            #@show data
        end
    end
end

"""
A function which one uses to forward forward traffic from multiple sockets into one socket by multiplexing.
"""
function route(ios::Vector{IO},socket)
    lines = [Line(socket,i) for i in 1:length(ios)]
    task = @async route(lines,socket)
    
    # Now I need to connect each line with each ios
    
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

#export serialize, deserialize, route, Line

