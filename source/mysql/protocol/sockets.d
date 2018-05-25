module mysql.protocol.sockets;

import std.exception;
import std.socket;

import mysql.exceptions;

alias OpenSocketCallback = TcpSocket function(string, ushort);

class MySQLSocket
{
    private TcpSocket socket;

    this(TcpSocket socket)
    {
        enforce!MYX(socket, "Tried to use a null Phobos socket - Maybe the 'openSocket' callback returned null?");
        enforce!MYX(socket.isAlive, "Tried to use a closed Phobos socket - Maybe the 'openSocket' callback created a socket but forgot to open it?");
        this.socket = socket;
    }

    invariant()
    {
        assert(!!socket);
    }

    void close()
    {
        socket.shutdown(SocketShutdown.BOTH);
        socket.close();
    }

    @property bool connected() const
    {
        return socket.isAlive;
    }

    void read(ubyte[] dst)
    {
        //scope(failure) socket.close();

        for (size_t off, len; off < dst.length; off += len) {
            len = socket.receive(dst[off..$]);
            enforce!MYX(len != 0, "Server closed the connection");
            enforce!MYX(len != socket.ERROR, "Received std.socket.Socket.ERROR");
        }
    }

    void write(in ubyte[] bytes)
    {
        for (size_t off, len; off < bytes.length; off += len) {
            len = socket.send(bytes[off..$]);
            enforce!MYX(len != 0, "Server closed the connection");
            enforce!MYX(len != socket.ERROR, "Received std.socket.Socket.ERROR");
        }
    }

    void acquire() { /+ Do nothing +/ }
    void release() { /+ Do nothing +/ }
    bool isOwner() { return true; }
    bool amOwner() { return true; }
}