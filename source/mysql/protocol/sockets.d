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
		enforceEx!MYX(socket, "Tried to use a null Phobos socket - Maybe the 'openSocket' callback returned null?");
		enforceEx!MYX(socket.isAlive, "Tried to use a closed Phobos socket - Maybe the 'openSocket' callback created a socket but forgot to open it?");
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
			enforceEx!MYX(len != 0, "Server closed the connection");
			enforceEx!MYX(len != socket.ERROR, "Received std.socket.Socket.ERROR");
		}
	}

	void write(in ubyte[] bytes)
	{
		socket.send(bytes);
	}

	void acquire() { /+ Do nothing +/ }
	void release() { /+ Do nothing +/ }
	bool isOwner() { return true; }
	bool amOwner() { return true; }
}