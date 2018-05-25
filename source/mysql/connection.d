module mysql.connection;

import std.algorithm;
import std.conv;
import std.digest.sha;
import std.exception;
import std.socket;
import std.string;

import mysql.commands;
import mysql.exceptions;
import mysql.protocol.constants;
import mysql.protocol.packets;
import mysql.protocol.sockets;
import mysql.result;
import mysql.prepared;

/// The default `mysql.protocol.constants.CapabilityFlags` used when creating a connection.
immutable CapabilityFlags defaultClientFlags =
		CapabilityFlags.OLD_LONG_PASSWORD | CapabilityFlags.ALL_COLUMN_FLAGS |
		CapabilityFlags.WITH_DB | CapabilityFlags.PROTOCOL41 |
		CapabilityFlags.SECURE_CONNECTION;// | CapabilityFlags.MULTI_STATEMENTS |
		//CapabilityFlags.MULTI_RESULTS;

class Connection
{

package:

	enum OpenState
	{
		notConnected,
		connected,
		authenticated
	}
	
	OpenState   _open;
	MySQLSocket _socket;

	CapabilityFlags _sCaps, _cCaps;
	uint    _sThread;
	ushort  _serverStatus;
	ubyte   _sCharSet, _protocol;
	string  _serverVersion;

	string _host, _user, _pwd, _db;
	ushort _port;

	OpenSocketCallback _openSocket;

	ulong _insertId;
	ulong _lastCommandId;
	bool _rowsPending, _headersPending, _binaryPending;
	ushort _fieldCount;

	ResultSetHeaders _rsh;

	ubyte _cpn; /// Packet Number in packet header. Serial number to ensure correct
				/// ordering. First packet should have 0
	@property ubyte pktNumber()   { return _cpn; }
	void bumpPacket()       { _cpn++; }
	void resetPacket()      { _cpn = 0; }

	// For mysql server not support prepared cache.
	bool allowClientPreparedCache_ = true;
	Prepared[string] clientPreparedCaches_;

	pure const nothrow invariant()
	{
	}

	void enforceNothingPending()
	{
		enforce!MYXDataPending(!hasPending);
	}

	ubyte[] getPacket()
	{
		//scope(failure) kill();

		ubyte[4] header;
		_socket.read(header);
		// number of bytes always set as 24-bit
		uint numDataBytes = (header[2] << 16) + (header[1] << 8) + header[0];
		enforce!MYXProtocol(header[3] == pktNumber, "Server packet out of order");
		bumpPacket();

		ubyte[] packet = new ubyte[numDataBytes];
		_socket.read(packet);
		assert(packet.length == numDataBytes, "Wrong number of bytes read");
		return packet;
	}

	void send(const(ubyte)[] packet)
	in
	{
		assert(packet.length > 4); // at least 1 byte more than header
	}
	body
	{
		_socket.write(packet);
	}

	void send(const(ubyte)[] header, const(ubyte)[] data)
	in
	{
		assert(header.length == 4 || header.length == 5/*command type included*/);
	}
	body
	{
		_socket.write(header);
		if(data.length)
			_socket.write(data);
	}

	void sendCmd(T)(CommandType cmd, const(T)[] data)
	in
	{
		// Internal thread states. Clients shouldn't use this
		assert(cmd != CommandType.SLEEP);
		assert(cmd != CommandType.CONNECT);
		assert(cmd != CommandType.TIME);
		assert(cmd != CommandType.DELAYED_INSERT);
		assert(cmd != CommandType.CONNECT_OUT);

		// Deprecated
		assert(cmd != CommandType.CREATE_DB);
		assert(cmd != CommandType.DROP_DB);
		assert(cmd != CommandType.TABLE_DUMP);

		// cannot send more than uint.max bytes. TODO: better error message if we try?
		assert(data.length <= uint.max);
	}
	out
	{
		// at this point we should have sent a command
		assert(pktNumber == 1);
	}
	body
	{
		enforce!MYX(!(_headersPending || _rowsPending),
			"There are result set elements pending - purgeResult() required.");

		scope(failure) kill();

		_lastCommandId++;

		if(!_socket.connected)
		{
			if(cmd == CommandType.QUIT)
				return; // Don't bother reopening connection just to quit

			_open = OpenState.notConnected;
			connect(_clientCapabilities);
		}

		resetPacket();

		ubyte[] header;
		header.length = 4 /*header*/ + 1 /*cmd*/;
		header.setPacketHeader(pktNumber, cast(uint)data.length +1/*cmd byte*/);
		header[4] = cmd;
		bumpPacket();

		send(header, cast(const(ubyte)[])data);
	}

	OKErrorPacket getCmdResponse(bool asString = false)
	{
		auto okp = OKErrorPacket(getPacket());
		enforcePacketOK(okp);
		_serverStatus = okp.serverStatus;
		return okp;
	}

	ubyte[] buildAuthPacket(ubyte[] token)
	in
	{
		assert(token.length == 20);
	}
	body
	{
		ubyte[] packet;
		packet.reserve(4/*header*/ + 4 + 4 + 1 + 23 + _user.length+1 + token.length+1 + _db.length+1);
		packet.length = 4 + 4 + 4; // create room for the beginning headers that we set rather than append

		// NOTE: we'll set the header last when we know the size

		// Set the default capabilities required by the client
		_cCaps.packInto(packet[4..8]);

		// Request a conventional maximum packet length.
		1.packInto(packet[8..12]);

		packet ~= 33; // Set UTF-8 as default charSet

		// There's a statutory block of zero bytes here - fill them in.
		foreach(i; 0 .. 23)
			packet ~= 0;

		// Add the user name as a null terminated string
		foreach(i; 0 .. _user.length)
			packet ~= _user[i];
		packet ~= 0; // \0

		// Add our calculated authentication token as a length prefixed string.
		assert(token.length <= ubyte.max);
		if(_pwd.length == 0)  // Omit the token if the account has no password
			packet ~= 0;
		else
		{
			packet ~= cast(ubyte)token.length;
			foreach(i; 0 .. token.length)
				packet ~= token[i];
		}

		// Add the default database as a null terminated string
		foreach(i; 0 .. _db.length)
			packet ~= _db[i];
		packet ~= 0; // \0

		// The server sent us a greeting with packet number 0, so we send the auth packet
		// back with the next number.
		packet.setPacketHeader(pktNumber);
		bumpPacket();
		return packet;
	}

	void consumeServerInfo(ref ubyte[] packet)
	{
		scope(failure) kill();

		_sCaps = cast(CapabilityFlags)packet.consume!ushort(); // server_capabilities (lower bytes)
		_sCharSet = packet.consume!ubyte(); // server_language
		_serverStatus = packet.consume!ushort(); //server_status
		_sCaps += cast(CapabilityFlags)(packet.consume!ushort() << 16); // server_capabilities (upper bytes)
		_sCaps |= CapabilityFlags.OLD_LONG_PASSWORD; // Assumed to be set since v4.1.1, according to spec

		enforce!MYX(_sCaps & CapabilityFlags.PROTOCOL41, "Server doesn't support protocol v4.1");
		enforce!MYX(_sCaps & CapabilityFlags.SECURE_CONNECTION, "Server doesn't support protocol v4.1 connection");
	}

	ubyte[] parseGreeting()
	{
		scope(failure) kill();

		ubyte[] packet = getPacket();

		if (packet.length > 0 && packet[0] == ResultPacketMarker.error)
		{
			auto okp = OKErrorPacket(packet);
			enforce!MYX(!okp.error, "Connection failure: " ~ cast(string) okp.message);
		}

		_protocol = packet.consume!ubyte();

		_serverVersion = packet.consume!string(packet.countUntil(0));
		packet.skip(1); // \0 terminated _serverVersion

		_sThread = packet.consume!uint();

		// read first part of scramble buf
		ubyte[] authBuf;
		authBuf.length = 255;
		authBuf[0..8] = packet.consume(8)[]; // scramble_buff

		enforce!MYXProtocol(packet.consume!ubyte() == 0, "filler should always be 0");

		consumeServerInfo(packet);

		packet.skip(1); // this byte supposed to be scramble length, but is actually zero
		packet.skip(10); // filler of \0

		// rest of the scramble
		auto len = packet.countUntil(0);
		enforce!MYXProtocol(len >= 12, "second part of scramble buffer should be at least 12 bytes");
		enforce(authBuf.length > 8+len);
		authBuf[8..8+len] = packet.consume(len)[];
		authBuf.length = 8+len; // cut to correct size
		enforce!MYXProtocol(packet.consume!ubyte() == 0, "Excepted \\0 terminating scramble buf");

		return authBuf;
	}

	static TcpSocket openSocket(string host, ushort port)
	{
		auto s = new TcpSocket();
		s.connect(new InternetAddress(host, port));
		return s;
	}

	void initConnection()
	{
		resetPacket();
		_socket = new MySQLSocket(_openSocket(_host, _port));
		clientPreparedCaches_.clear;
	}

	ubyte[] makeToken(ubyte[] authBuf)
	{
		auto pass1 = sha1Of(cast(const(ubyte)[])_pwd);
		auto pass2 = sha1Of(pass1);

		SHA1 sha1;
		sha1.start();
		sha1.put(authBuf);
		sha1.put(pass2);
		auto result = sha1.finish();
		foreach (size_t i; 0..20)
			result[i] = result[i] ^ pass1[i];
		return result.dup;
	}

	CapabilityFlags getCommonCapabilities(CapabilityFlags server, CapabilityFlags client) pure
	{
		CapabilityFlags common;
		uint filter = 1;
		foreach (size_t i; 0..uint.sizeof)
		{
			bool serverSupport = (server & filter) != 0; // can the server do this capability?
			bool clientSupport = (client & filter) != 0; // can we support it?
			if(serverSupport && clientSupport)
				common |= filter;
			filter <<= 1; // check next flag
		}
		return common;
	}

	void setClientFlags(CapabilityFlags caps)
	{
		_cCaps = getCommonCapabilities(_sCaps, caps);

		// We cannot operate in <4.1 protocol, so we'll force it even if the user
		// didn't supply it
		_cCaps |= CapabilityFlags.PROTOCOL41;
		_cCaps |= CapabilityFlags.SECURE_CONNECTION;
	}

	void authenticate(ubyte[] greeting)
	in
	{
		assert(_open == OpenState.connected);
	}
	out
	{
		assert(_open == OpenState.authenticated);
	}
	body
	{
		auto token = makeToken(greeting);
		auto authPacket = buildAuthPacket(token);
		send(authPacket);

		auto packet = getPacket();
		auto okp = OKErrorPacket(packet);
		enforce!MYX(!okp.error, "Authentication failure: " ~ cast(string) okp.message);
		_open = OpenState.authenticated;
	}

	CapabilityFlags _clientCapabilities;

	void connect(CapabilityFlags clientCapabilities)
	in
	{
		assert(closed);
	}
	out
	{
		assert(_open == OpenState.authenticated);
	}
	body
	{
		initConnection();
		auto greeting = parseGreeting();
		_open = OpenState.connected;

		_clientCapabilities = clientCapabilities;
		setClientFlags(clientCapabilities);
		authenticate(greeting);
	}
	
	void kill()
	{
		if(_socket.connected)
			_socket.close();
		_open = OpenState.notConnected;
	}

package:

    bool _busy = false;

    @property bool busy()
    {
        return _busy;
    }

    @property void busy(bool value)
    {
        _busy = value;
    }

public:

	this(string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags caps = defaultClientFlags)
	{
		this(&openSocket,
			host, user, pwd, db, port, caps);
	}

	private this(
		OpenSocketCallback openSocket,
		string host, string user, string pwd, string db, ushort port = 3306, CapabilityFlags caps = defaultClientFlags)
	{
		enforce!MYX(caps & CapabilityFlags.PROTOCOL41, "This client only supports protocol v4.1");
		enforce!MYX(caps & CapabilityFlags.SECURE_CONNECTION, "This client only supports protocol v4.1 connection");

		_host = host;
		_user = user;
		_pwd  = pwd;
		_db   = db;
		_port = port;

		_openSocket = openSocket;

		connect(caps);
	}

	this(string cs, CapabilityFlags caps = defaultClientFlags)
	{
		string[] a = parseConnectionString(cs);
		this(a[0], a[1], a[2], a[3], to!ushort(a[4]), caps);
	}

	this(OpenSocketCallback openSocket, string cs, CapabilityFlags caps = defaultClientFlags)
	{
		string[] a = parseConnectionString(cs);
		this(openSocket, a[0], a[1], a[2], a[3], to!ushort(a[4]), caps);
	}

	@property bool closed()
	{
		return _open == OpenState.notConnected || !_socket.connected;
	}

	/// Used by Vibe.d's ConnectionPool, ignore this.
	void acquire() { /+ Do nothing +/ }
	///ditto
	void release() { /+ Do nothing +/ }
	///ditto
	bool isOwner() { return !!_socket; }
	///ditto
	bool amOwner() { return !!_socket; }

	void close()
	{
		if (_open == OpenState.authenticated && _socket.connected)
			quit();

		if (_open == OpenState.connected)
			kill();
		resetPacket();
	}

	void reconnect()
	{
		reconnect(_clientCapabilities);
	}

	void reconnect(CapabilityFlags clientCapabilities)
	{
		bool sameCaps = clientCapabilities == _clientCapabilities;
		if(!closed)
		{
			// Same caps as before?
			if(clientCapabilities == _clientCapabilities)
				return; // Nothing to do, just keep current connection

			close();
		}

		connect(clientCapabilities);
	}

	private void quit()
	in
	{
		assert(_open == OpenState.authenticated);
	}
	body
	{
		sendCmd(CommandType.QUIT, []);
		// No response is sent for a quit packet
		_open = OpenState.connected;
	}

	private bool inTransaction()
	{
		return ((serverStatus & 0x0001) != 0);
	}

	void startTransaction(string File=__FILE__, size_t Line=__LINE__)()
	{
		if (inTransaction)
			throw new Exception("MySQL does not support nested transactions - commit or rollback before starting a new transaction", File, Line);

		exec(this, "start transaction");
		
		assert(inTransaction);
	}

	void rollback(string File=__FILE__, size_t Line=__LINE__)()
	{
		if (!inTransaction)
			throw new Exception("No active transaction", File, Line);
			
		exec(this, "rollback");

		assert(!inTransaction);
	}
	
	void commit(string File=__FILE__, size_t Line=__LINE__)()
	{
		if (!inTransaction)
			throw new Exception("No active transaction", File, Line);
			
		exec(this, "commit");

		assert(!inTransaction);
	}

	static string[] parseConnectionString(string cs)
	{
		string[] rv;
		rv.length = 5;
		rv[4] = "3306"; // Default port
		string[] a = split(cs, ";");
		foreach (s; a)
		{
			string[] a2 = split(s, "=");
			enforce!MYX(a2.length == 2, "Bad connection string: " ~ cs);
			string name = strip(a2[0]);
			string val = strip(a2[1]);
			switch (name)
			{
				case "host":
					rv[0] = val;
					break;
				case "user":
					rv[1] = val;
					break;
				case "pwd":
					rv[2] = val;
					break;
				case "db":
					rv[3] = val;
					break;
				case "port":
					rv[4] = val;
					break;
				default:
					throw new MYX("Bad connection string: " ~ cs, __FILE__, __LINE__);
			}
		}
		return rv;
	}

	void selectDB(string dbName)
	{
		sendCmd(CommandType.INIT_DB, dbName);
		getCmdResponse();
		_db = dbName;
	}

	OKErrorPacket pingServer()
	{
		sendCmd(CommandType.PING, []);
		return getCmdResponse();
	}

	OKErrorPacket refreshServer(RefreshFlags flags)
	{
		sendCmd(CommandType.REFRESH, [flags]);
		return getCmdResponse();
	}

	Row getNextRow()
	{
		scope(failure) kill();

		if (_headersPending)
		{
			_rsh = ResultSetHeaders(this, _fieldCount);
			_headersPending = false;
		}
		ubyte[] packet;
		Row rr;
		packet = getPacket();
		if (packet.isEOFPacket())
		{
			_rowsPending = _binaryPending = false;
			return rr;
		}
		if (_binaryPending)
			rr = Row(this, packet, _rsh, true);
		else
			rr = Row(this, packet, _rsh, false);
		//rr._valid = true;
		return rr;
	}

	ulong purgeResult()
	{
		scope(failure) kill();

		_lastCommandId++;

		ulong rows = 0;
		if (_headersPending)
		{
			for (size_t i = 0;; i++)
			{
				if (getPacket().isEOFPacket())
				{
					_headersPending = false;
					break;
				}
				enforce!MYXProtocol(i < _fieldCount,
					text("Field header count (", _fieldCount, ") exceeded but no EOF packet found."));
			}
		}
		if (_rowsPending)
		{
			for (;;  rows++)
			{
				if (getPacket().isEOFPacket())
				{
					_rowsPending = _binaryPending = false;
					break;
				}
			}
		}
		resetPacket();
		return rows;
	}

	string serverStats()
	{
		sendCmd(CommandType.STATISTICS, []);
		return cast(string) getPacket();
	}

	void enableMultiStatements(bool on)
	{
		scope(failure) kill();

		ubyte[] t;
		t.length = 2;
		t[0] = on ? 0 : 1;
		t[1] = 0;
		sendCmd(CommandType.STMT_OPTION, t);

		// For some reason this command gets an EOF packet as response
		auto packet = getPacket();
		enforce!MYXProtocol(packet[0] == 254 && packet.length == 5, "Unexpected response to SET_OPTION command");
	}

	/// Return the in-force protocol number
	@property ubyte protocol() pure const nothrow { return _protocol; }
	/// Server version
	@property string serverVersion() pure const nothrow { return _serverVersion; }
	/// Server capability flags
	@property uint serverCapabilities() pure const nothrow { return _sCaps; }
	/// Server status
	@property ushort serverStatus() pure const nothrow { return _serverStatus; }
	/// Current character set
	@property ubyte charSet() pure const nothrow { return _sCharSet; }
	/// Current database
	@property string currentDB() pure const nothrow { return _db; }

	@property ulong lastInsertId() pure const nothrow { return _insertId; }

	@property ulong lastCommandId() pure const nothrow { return _lastCommandId; }

	/// Gets whether rows are pending
	@property bool rowsPending() pure const nothrow { return _rowsPending; }

	/// Gets whether anything (rows, headers or binary) is pending.
	/// New commands cannot be sent on a conncection while anything is pending.
	@property bool hasPending() pure const nothrow
	{
		return _rowsPending || _headersPending || _binaryPending;
	}

	/// Gets the result header's field descriptions.
	@property FieldDescription[] resultFieldDescriptions() pure { return _rsh.fieldDescriptions; }

	@property void allowClientPreparedCache(bool enable) {
		allowClientPreparedCache_ = enable;
	}
	
	@property bool allowClientPreparedCache() {
		return allowClientPreparedCache_;
	}
	
	@property Prepared[string] clientPreparedCaches() {
		return clientPreparedCaches_;
	}
	
	void putPreparedCache(string sql, Prepared stmt) {
		clientPreparedCaches_[sql] = stmt;
	}
}
