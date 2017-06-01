/++
Use a DB via plain SQL statements.

Commands that are expected to return a result set - queries - have distinctive
methods that are enforced. That is it will be an error to call such a method
with an SQL command that does not produce a result set. So for commands like
SELECT, use the `query` functions. For other commands, like
INSERT/UPDATE/CREATE/etc, use `exec`.
+/

module mysql.commands;

import std.conv;
import std.exception;
import std.range;
import std.typecons;
import std.variant;

import mysql.connection;
import mysql.exceptions;
import mysql.prepared;
import mysql.protocol.constants;
import mysql.protocol.extra_types;
import mysql.protocol.packets;
import mysql.protocol.packet_helpers;
import mysql.protocol.sockets;
import mysql.result;

/++
A struct to represent specializations of prepared statement parameters.

If you are executing a query that will include result columns that are large objects
it may be expedient to deal with the data as it is received rather than first buffering
it to some sort of byte array. These two variables allow for this. If both are provided
then the corresponding column will be fed to the stipulated delegate in chunks of
chunkSize, with the possible exception of the last chunk, which may be smaller.
The 'finished' argument will be set to true when the last chunk is set.

Be aware when specifying types for column specializations that for some reason the
field descriptions returned for a resultset have all of the types TINYTEXT, MEDIUMTEXT,
TEXT, LONGTEXT, TINYBLOB, MEDIUMBLOB, BLOB, and LONGBLOB lumped as type 0xfc
contrary to what it says in the protocol documentation.
+/
struct ColumnSpecialization
{
	size_t  cIndex;    // parameter number 0 - number of params-1
	ushort  type;
	uint    chunkSize;
	void delegate(const(ubyte)[] chunk, bool finished) chunkDelegate;
}
///ditto
alias CSN = ColumnSpecialization;

package struct ExecQueryImplInfo
{
	bool isPrepared;

	// For non-prepared statements:
	string sql;

	// For prepared statements:
	uint hStmt;
	PreparedStmtHeaders psh;
	Variant[] inParams;
	ParameterSpecialization[] psa;
}

/++
Internal implementation for the exec and query functions.

Execute a one-off SQL command.

Use this method when you are not going to be using the same command repeatedly.
It can be used with commands that don't produce a result set, or those that
do. If there is a result set its existence will be indicated by the return value.

Any result set can be accessed via Connection.getNextRow(), but you should really be
using the query function for such queries.

Params: ra = An out parameter to receive the number of rows affected.
Returns: true if there was a (possibly empty) result set.
+/
package bool execQueryImpl(Connection conn, ExecQueryImplInfo info, out ulong ra)
{
	conn.enforceNothingPending();
	scope(failure) conn.kill();

	// Send data
	if(info.isPrepared)
		Prepared.sendCommand(conn, info.hStmt, info.psh, info.inParams, info.psa);
	else
	{
		conn.sendCmd(CommandType.QUERY, info.sql);
		conn._fieldCount = 0;
	}

	// Handle response
	ubyte[] packet = conn.getPacket();
	bool rv;
	if (packet.front == ResultPacketMarker.ok || packet.front == ResultPacketMarker.error)
	{
		conn.resetPacket();
		auto okp = OKErrorPacket(packet);
		enforcePacketOK(okp);
		ra = okp.affected;
		conn._serverStatus = okp.serverStatus;
		conn._insertID = okp.insertID;
		rv = false;
	}
	else
	{
		// There was presumably a result set
		assert(packet.front >= 1 && packet.front <= 250); // ResultSet packet header should have this value
		conn._headersPending = conn._rowsPending = true;
		conn._binaryPending = info.isPrepared;
		auto lcb = packet.consumeIfComplete!LCB();
		assert(!lcb.isNull);
		assert(!lcb.isIncomplete);
		conn._fieldCount = cast(ushort)lcb.value;
		assert(conn._fieldCount == lcb.value);
		rv = true;
		ra = 0;
	}
	return rv;
}

///ditto
package bool execQueryImpl(Connection conn, ExecQueryImplInfo info)
{
	ulong rowsAffected;
	return execQueryImpl(conn, info, rowsAffected);
}

/++
Execute a one-off SQL command, such as INSERT/UPDATE/CREATE/etc.

This method is intended for commands such as which do not produce a result set
(otherwise, use one of the query functions instead.) If the SQL command does
produces a result set (such as SELECT), `mysql.exceptions.MySQLResultRecievedException`
will be thrown.

Use this method when you are not going to be using the same command
repeatedly and you are CERTAIN all the data you're sending is properly
escaped. Otherwise consider using `mysql.prepared.Prepared`.

Params:
conn = An open Connection to the database.
sql = The SQL command to be run.

Returns: The number of rows affected.
+/
ulong exec(Connection conn, string sql)
{
	return execImpl(conn, ExecQueryImplInfo(false, sql));
}

/// Common implementation for mysql.commands.exec and Prepared.exec
package ulong execImpl(Connection conn, ExecQueryImplInfo info)
{
	ulong rowsAffected;
	bool receivedResultSet = execQueryImpl(conn, info, rowsAffected);
	if(receivedResultSet)
	{
		conn.purgeResult();
		throw new MYXResultRecieved();
	}

	return rowsAffected;
}

/++
Execute a one-off SQL SELECT command where you expect the entire
result set all at once.

This is being considered for deprecation in a future release of mysql-native,
because the same thing can be achieved via `query`().
$(LINK2 https://dlang.org/phobos/std_array.html#array, `array()`).

If the SQL command does not produce a result set (such as INSERT/CREATE/etc),
then `mysql.exceptions.MySQLNoResultRecievedException` will be thrown. Use
`exec` instead for such commands.

Use this method when you are not going to be using the same command
repeatedly and you are CERTAIN all the data you're sending is properly
escaped. Otherwise consider using `mysql.prepared.Prepared`.

If there are long data items among the expected result columns you can use
the csa param to specify that they are to be subject to chunked transfer via a
delegate.

Params:
conn = An open Connection to the database.
sql = The SQL command to be run.
csa = An optional array of ColumnSpecialization structs.

Returns: A (possibly empty) ResultSet.
+/
ResultSet querySet(Connection conn, string sql, ColumnSpecialization[] csa = null)
{
	return querySetImpl(csa, false, conn, ExecQueryImplInfo(false, sql));
}

///ditto
deprecated("Use querySet instead.")
alias queryResult = querySet;

/// Common implementation for mysql.commands.querySet and Prepared.querySet
package ResultSet querySetImpl(ColumnSpecialization[] csa, bool binary,
	Connection conn, ExecQueryImplInfo info)
{
	ulong ra;
	enforceEx!MYXNoResultRecieved(execQueryImpl(conn, info, ra));

	conn._rsh = ResultSetHeaders(conn, conn._fieldCount);
	if (csa !is null)
		conn._rsh.addSpecializations(csa);
	conn._headersPending = false;

	Row[] rows;
	while(true)
	{
		scope(failure) conn.kill();

		auto packet = conn.getPacket();
		if(packet.isEOFPacket())
			break;
		rows ~= Row(conn, packet, conn._rsh, binary);
		// As the row fetches more data while incomplete, it might already have
		// fetched the EOF marker, so we have to check it again
		if(!packet.empty && packet.isEOFPacket())
			break;
	}
	conn._rowsPending = conn._binaryPending = false;

	return ResultSet(rows, conn._rsh.fieldNames);
}

/++
Execute a one-off SQL SELECT command where you want to deal with the
result set one row at a time.

If you need random access to the resulting Row elements,
simply call $(LINK2 https://dlang.org/phobos/std_array.html#array, `std.array.array()`)
on the result.

If the SQL command does not produce a result set (such as INSERT/CREATE/etc),
then `mysql.exceptions.MySQLNoResultRecievedException` will be thrown. Use
`exec` instead for such commands.

Use this method when you are not going to be using the same command
repeatedly and you are CERTAIN all the data you're sending is properly
escaped. Otherwise consider using `mysql.prepared.Prepared`.

If there are long data items among the expected result columns you can use
the csa param to specify that they are to be subject to chunked transfer via a
delegate.

Params:
conn = An open Connection to the database.
sql = The SQL command to be run.
csa = An optional array of ColumnSpecialization structs.

Returns: A (possibly empty) ResultRange.
+/
ResultRange query(Connection conn, string sql, ColumnSpecialization[] csa = null)
{
	return queryImpl(csa, conn, ExecQueryImplInfo(false, sql));
}

///ditto
deprecated("Use query instead.")
alias querySequence = query;

/// Common implementation for mysql.commands.query and Prepared.query
package ResultRange queryImpl(ColumnSpecialization[] csa,
	Connection conn, ExecQueryImplInfo info)
{
	ulong ra;
	enforceEx!MYXNoResultRecieved(execQueryImpl(conn, info, ra));

	conn._rsh = ResultSetHeaders(conn, conn._fieldCount);
	if (csa !is null)
		conn._rsh.addSpecializations(csa);

	conn._headersPending = false;
	return ResultRange(conn, conn._rsh, conn._rsh.fieldNames);
}

/++
Execute a one-off SQL SELECT command where you only want the first Row (if any).

If the SQL command does not produce a result set (such as INSERT/CREATE/etc),
then `mysql.exceptions.MySQLNoResultRecievedException` will be thrown. Use
`exec` instead for such commands.

Use this method when you are not going to be using the same command
repeatedly and you are CERTAIN all the data you're sending is properly
escaped. Otherwise consider using `mysql.prepared.Prepared`.

If there are long data items among the expected result columns you can use
the csa param to specify that they are to be subject to chunked transfer via a
delegate.

Params:
conn = An open Connection to the database.
sql = The SQL command to be run.
csa = An optional array of ColumnSpecialization structs.

Returns: Nullable!Row: This will be null (check via Nullable.isNull) if the
query resulted in an empty result set.
+/
Nullable!Row queryRow(Connection conn, string sql, ColumnSpecialization[] csa = null)
{
	return queryRowImpl(csa, conn, ExecQueryImplInfo(false, sql));
}

/// Common implementation for mysql.commands.querySet and Prepared.querySet
package Nullable!Row queryRowImpl(ColumnSpecialization[] csa, Connection conn,
	ExecQueryImplInfo info)
{
	auto results = queryImpl(csa, conn, info);
	if(results.empty)
		return Nullable!Row();
	else
	{
		auto row = results.front;
		results.close();
		return Nullable!Row(row);
	}
}

/++
Execute a one-off SQL SELECT command where you only want the first Row, and
place result values into a set of D variables.

This method will throw if any column type is incompatible with the corresponding D variable.

Unlike the other query functions, queryRowTuple will throw
`mysql.exceptions.MySQLException` if the result set is empty
(and thus the reference variables passed in cannot be filled).

If the SQL command does not produce a result set (such as INSERT/CREATE/etc),
then `mysql.exceptions.MySQLNoResultRecievedException` will be thrown. Use
`exec` instead for such commands.

Use this method when you are not going to be using the same command
repeatedly and you are CERTAIN all the data you're sending is properly
escaped. Otherwise consider using `mysql.prepared.Prepared`.

Params:
conn = An open Connection to the database.
sql = The SQL command to be run.
args = The variables, taken by reference, to receive the values.

Params: args = A tuple of D variables to receive the results.
+/
void queryRowTuple(T...)(Connection conn, string sql, ref T args)
{
	return queryRowTupleImpl(conn, ExecQueryImplInfo(false, sql), args);
}

///ditto
deprecated("Use queryRowTuple instead.")
alias queryTuple = queryRowTuple;

/// Common implementation for mysql.commands.queryRowTuple and Prepared.queryRowTuple
package void queryRowTupleImpl(T...)(Connection conn, ExecQueryImplInfo info, ref T args)
{
	ulong ra;
	enforceEx!MYXNoResultRecieved(execQueryImpl(conn, info, ra));

	Row rr = conn.getNextRow();
	/+if (!rr._valid)   // The result set was empty - not a crime.
		return;+/
	enforceEx!MYX(rr._values.length == args.length, "Result column count does not match the target tuple.");
	foreach (size_t i, dummy; args)
	{
		enforceEx!MYX(typeid(args[i]).toString() == rr._values[i].type.toString(),
			"Tuple "~to!string(i)~" type and column type are not compatible.");
		args[i] = rr._values[i].get!(typeof(args[i]));
	}
	// If there were more rows, flush them away
	// Question: Should I check in purgeResult and throw if there were - it's very inefficient to
	// allow sloppy SQL that does not ensure just one row!
	conn.purgeResult();
}

// Test what happends when queryRowTuple receives no rows
debug(MYSQL_INTEGRATION_TESTS)
unittest
{
	import mysql.prepared;
	import mysql.test.common : scopedCn, createCn;
	mixin(scopedCn);

	cn.exec("DROP TABLE IF EXISTS `queryRowTuple`");
	cn.exec("CREATE TABLE `queryRowTuple` (
		`val` INTEGER
	) ENGINE=InnoDB DEFAULT CHARSET=utf8");

	immutable selectSQL = "SELECT * FROM `queryRowTuple`";
	int queryTupleResult;
	assertThrown!MYX(cn.queryRowTuple(selectSQL, queryTupleResult));
}

/++
Execute a one-off SQL SELECT command and returns a single value,
the first column of the first row received.

If the query did not produce any rows, or the rows it produced have zero columns,
this will return `Nullable!Variant()`, ie, null. Test for this with `result.isNull`.

If the query DID produce a result, but the value actually received is NULL,
then `result.isNull` will be FALSE, and `result.get` will produce a Variant
which CONTAINS null. Check for this with `result.get.type == typeid(typeof(null))`.

If the SQL command does not produce a result set (such as INSERT/CREATE/etc),
then `mysql.exceptions.MySQLNoResultRecievedException` will be thrown. Use
`exec` instead for such commands.

Use this method when you are not going to be using the same command
repeatedly and you are CERTAIN all the data you're sending is properly
escaped. Otherwise consider using `mysql.prepared.Prepared`.

If there are long data items among the expected result columns you can use
the csa param to specify that they are to be subject to chunked transfer via a
delegate.

Params:
conn = An open Connection to the database.
sql = The SQL command to be run.
csa = An optional array of ColumnSpecialization structs.

Returns: Nullable!Variant: This will be null (check via Nullable.isNull) if the
query resulted in an empty result set.
+/
Nullable!Variant queryValue(Connection conn, string sql, ColumnSpecialization[] csa = null)
{
	return queryValueImpl(csa, conn, ExecQueryImplInfo(false, sql));
}

/// Common implementation for mysql.commands.querySet and Prepared.querySet
package Nullable!Variant queryValueImpl(ColumnSpecialization[] csa, Connection conn,
	ExecQueryImplInfo info)
{
	auto results = queryImpl(csa, conn, info);
	if(results.empty)
		return Nullable!Variant();
	else
	{
		auto row = results.front;
		results.close();
		
		if(row.length == 0)
			return Nullable!Variant();
		else
			return Nullable!Variant(row[0]);
	}
}

/++
(deprecated) Encapsulation of an SQL command or query.

A Command be be either a one-off SQL query, or may use a prepared statement.
Commands that are expected to return a result set - queries - have distinctive methods
that are enforced. That is it will be an error to call such a method with an SQL command
that does not produce a result set.
+/
struct Command
{
package:
	Connection _con;    // This can disappear along with Command
	string _sql; // This can disappear along with Command
	string _prevFunc; // Has to do with stored procedures
	Prepared _prepared; // The current prepared statement info

public:

	/++
	Construct a naked Command object
	
	Params: con = A Connection object to communicate with the server
	+/
	// This can disappear along with Command
	this(Connection con)
	{
		_con = con;
		_con.resetPacket();
	}

	/++
	Construct a Command object complete with SQL
	
	Params: con = A Connection object to communicate with the server
	               sql = SQL command string.
	+/
	// This can disappear along with Command
	this(Connection con, const(char)[] sql)
	{
		_sql = sql.idup;
		this(con);
	}

	@property
	{
		/// Get the current SQL for the Command
		// This can disappear along with Command
		const(char)[] sql() pure const nothrow { return _sql; }

		/++
		Set a new SQL command.
		
		This can have quite profound side effects. It resets the Command to
		an initial state. If a query has been issued on the Command that
		produced a result set, then all of the result set packets - field
		description sequence, EOF packet, result rows sequence, EOF packet
		must be flushed from the server before any further operation can be
		performed on the Connection. If you want to write speedy and efficient
		MySQL programs, you should bear this in mind when designing your
		queries so that you are not requesting many rows when one would do.
		
		Params: sql = SQL command string.
		+/
		// This can disappear along with Command
		const(char)[] sql(const(char)[] sql)
		{
			if (_prepared.isPrepared)
			{
				_prepared.release();
				_prevFunc = null; 
			}
			return this._sql = sql.idup;
		}
	}

	/++
	Submit an SQL command to the server to be compiled into a prepared statement.
	
	The result of a successful outcome will be a statement handle - an ID -
	for the prepared statement, a count of the parameters required for
	excution of the statement, and a count of the columns that will be present
	in any result set that the command generates. Thes values will be stored
	in in the Command struct.
	
	The server will then proceed to send prepared statement headers,
	including parameter descriptions, and result set field descriptions,
	followed by an EOF packet.
	
	If there is an existing statement handle in the Command struct, that
	prepared statement is released.
	
	Throws: MySQLException if there are pending result set items, or if the
	server has a problem.
	+/
	deprecated("Use Prepare.this(Connection conn, string sql) instead")
	void prepare()
	{
		_prepared = .prepare(_con, _sql);
	}

	/++
	Release a prepared statement.
	
	This method tells the server that it can dispose of the information it
	holds about the current prepared statement, and resets the Command
	object to an initial state in that respect.
	+/
	deprecated("Use Prepared.release instead")
	void releaseStatement()
	{
		if (_prepared.isPrepared)
			_prepared.release();
	}

	/++
	Flush any outstanding result set elements.
	
	When the server responds to a command that produces a result set, it
	queues the whole set of corresponding packets over the current connection.
	Before that Connection can embark on any new command, it must receive
	all of those packets and junk them.
	http://www.mysqlperformanceblog.com/2007/07/08/mysql-net_write_timeout-vs-wait_timeout-and-protocol-notes/
	+/
	deprecated("Use Connection.purgeResult() instead.")
	ulong purgeResult()
	{
		return _con.purgeResult();
	}

	/++
	Bind a D variable to a prepared statement parameter.
	
	In this implementation, binding comprises setting a value into the
	appropriate element of an array of Variants which represent the
	parameters, and setting any required specializations.
	
	To bind to some D variable, we set the corrsponding variant with its
	address, so there is no need to rebind between calls to execPreparedXXX.
	+/
	deprecated("Use Prepared.setArg instead")
	void bindParameter(T)(ref T val, size_t pIndex, ParameterSpecialization psn = PSN(0, SQLType.INFER_FROM_D_TYPE, 0, null))
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared before parameters are bound.");
		_prepared.setArg(pIndex, &val, psn);
	}

	/++
	Bind a tuple of D variables to the parameters of a prepared statement.
	
	You can use this method to bind a set of variables if you don't need any specialization,
	that is there will be no null values, and chunked transfer is not neccessary.
	
	The tuple must match the required number of parameters, and it is the programmer's
	responsibility to ensure that they are of appropriate types.
	+/
	deprecated("Use Prepared.setArgs instead")
	void bindParameterTuple(T...)(ref T args)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared before parameters are bound.");
		enforceEx!MYX(args.length == _prepared.numArgs, "Argument list supplied does not match the number of parameters.");
		foreach (size_t i, dummy; args)
			_prepared.setArg(&args[i], i);
	}

	/++
	Bind a Variant[] as the parameters of a prepared statement.
	
	You can use this method to bind a set of variables in Variant form to
	the parameters of a prepared statement.
	
	Parameter specializations can be added if required. This method could be
	used to add records from a data entry form along the lines of
	------------
	auto c = Command(con, "insert into table42 values(?, ?, ?)");
	c.prepare();
	Variant[] va;
	va.length = 3;
	DataRecord dr;    // Some data input facility
	ulong ra;
	do
	{
	    dr.get();
	    va[0] = dr("Name");
	    va[1] = dr("City");
	    va[2] = dr("Whatever");
	    c.bindParameters(va);
	    c.execPrepared(ra);
	} while(tod < "17:30");
	------------
	Params: va = External list of Variants to be used as parameters
	               psnList = any required specializations
	+/
	deprecated("Use Prepared.setArgs instead")
	void bindParameters(Variant[] va, ParameterSpecialization[] psnList= null)
	{
		_prepared.setArgs(va, psnList);
	}

	/++
	Access a prepared statement parameter for update.
	
	Another style of usage would simply update the parameter Variant directly
	
	------------
	c.param(0) = 42;
	c.param(1) = "The answer";
	------------
	Params: index = The zero based index
	+/
	deprecated("Use Prepared.getArg to get and Prepared.setArg to set.")
	ref Variant param(size_t index) pure
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared before parameters are bound.");
		enforceEx!MYX(index < _prepared.numArgs, "Parameter index out of range.");
		return _prepared._inParams[index];
	}

	/++
	Prepared statement parameter getter.

	Params: index = The zero based index
	+/
	deprecated("Use Prepared.getArg instead.")
	Variant getArg(size_t index)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared before parameters are bound.");
		return _prepared.getArg(index);
	}

	/++
	Sets a prepared statement parameter to NULL.
	
	Params: index = The zero based index
	+/
	deprecated("Use Prepared.setNullArg instead.")
	void setNullParam(size_t index)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared before parameters are bound.");
		_prepared.setNullArg(index);
	}

	/++
	Execute a one-off SQL command.
	
	Use this method when you are not going to be using the same command repeatedly.
	It can be used with commands that don't produce a result set, or those that
	do. If there is a result set its existence will be indicated by the return value.
	
	Any result set can be accessed vis Connection.getNextRow(), but you should really be
	using execSQLResult() or execSQLSequence() for such queries.
	
	Params: ra = An out parameter to receive the number of rows affected.
	Returns: true if there was a (possibly empty) result set.
	+/
	deprecated("Use the free-standing function .exec instead")
	bool execSQL(out ulong ra)
	{
		return .execQueryImpl(_con, ExecQueryImplInfo(false, _sql), ra);
	}

	///ditto
	deprecated("Use the free-standing function .exec instead")
	bool execSQL()
	{
		ulong ra;
		return .execQueryImpl(_con, ExecQueryImplInfo(false, _sql), ra);
	}
	
	/++
	Execute a one-off SQL command for the case where you expect a result set,
	and want it all at once.
	
	Use this method when you are not going to be using the same command repeatedly.
	This method will throw if the SQL command does not produce a result set.
	
	If there are long data items among the expected result columns you can specify
	that they are to be subject to chunked transfer via a delegate.
	
	Params: csa = An optional array of ColumnSpecialization structs.
	Returns: A (possibly empty) ResultSet.
	+/
	deprecated("Use the free-standing function .querySet instead")
	ResultSet execSQLResult(ColumnSpecialization[] csa = null)
	{
		return .querySet(_con, _sql, csa);
	}

	/++
	Execute a one-off SQL command for the case where you expect a result set,
	and want to deal with it a row at a time.
	
	Use this method when you are not going to be using the same command repeatedly.
	This method will throw if the SQL command does not produce a result set.
	
	If there are long data items among the expected result columns you can specify
	that they are to be subject to chunked transfer via a delegate.

	Params: csa = An optional array of ColumnSpecialization structs.
	Returns: A (possibly empty) ResultRange.
	+/
	deprecated("Use the free-standing function .query instead")
	ResultRange execSQLSequence(ColumnSpecialization[] csa = null)
	{
		return .query(_con, _sql, csa);
	}

	/++
	Execute a one-off SQL command to place result values into a set of D variables.
	
	Use this method when you are not going to be using the same command repeatedly.
	It will throw if the specified command does not produce a result set, or if
	any column type is incompatible with the corresponding D variable.
	
	Params: args = A tuple of D variables to receive the results.
	Returns: true if there was a (possibly empty) result set.
	+/
	deprecated("Use the free-standing function .queryRowTuple instead")
	void execSQLTuple(T...)(ref T args)
	{
		.queryRowTuple(_con, _sql, args);
	}

	/++
	Execute a prepared command.
	
	Use this method when you will use the same SQL command repeatedly.
	It can be used with commands that don't produce a result set, or those that
	do. If there is a result set its existence will be indicated by the return value.
	
	Any result set can be accessed vis Connection.getNextRow(), but you should really be
	using execPreparedResult() or execPreparedSequence() for such queries.
	
	Params: ra = An out parameter to receive the number of rows affected.
	Returns: true if there was a (possibly empty) result set.
	+/
	deprecated("Use Prepared.exec instead")
	bool execPrepared(out ulong ra)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared.");
		return _prepared.execQueryImpl2(ra);
	}

	/++
	Execute a prepared SQL command for the case where you expect a result set,
	and want it all at once.
	
	Use this method when you will use the same command repeatedly.
	This method will throw if the SQL command does not produce a result set.
	
	If there are long data items among the expected result columns you can specify
	that they are to be subject to chunked transfer via a delegate.
	
	Params: csa = An optional array of ColumnSpecialization structs.
	Returns: A (possibly empty) ResultSet.
	+/
	deprecated("Use Prepared.querySet instead")
	ResultSet execPreparedResult(ColumnSpecialization[] csa = null)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared.");
		return _prepared.querySet(csa);
	}

	/++
	Execute a prepared SQL command for the case where you expect a result set,
	and want to deal with it one row at a time.
	
	Use this method when you will use the same command repeatedly.
	This method will throw if the SQL command does not produce a result set.
	
	If there are long data items among the expected result columns you can
	specify that they are to be subject to chunked transfer via a delegate.

	Params: csa = An optional array of ColumnSpecialization structs.
	Returns: A (possibly empty) ResultRange.
	+/
	deprecated("Use Prepared.query instead")
	ResultRange execPreparedSequence(ColumnSpecialization[] csa = null)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared.");
		return _prepared.query(csa);
	}

	/++
	Execute a prepared SQL command to place result values into a set of D variables.
	
	Use this method when you will use the same command repeatedly.
	It will throw if the specified command does not produce a result set, or
	if any column type is incompatible with the corresponding D variable
	
	Params: args = A tuple of D variables to receive the results.
	Returns: true if there was a (possibly empty) result set.
	+/
	deprecated("Use Prepared.queryRowTuple instead")
	void execPreparedTuple(T...)(ref T args)
	{
		enforceEx!MYX(_prepared.isPrepared, "The statement must be prepared.");
		_prepared.queryRowTuple(args);
	}

	/++
	Get the next Row of a pending result set.
	
	This method can be used after either execSQL() or execPrepared() have returned true
	to retrieve result set rows sequentially.
	
	Similar functionality is available via execSQLSequence() and execPreparedSequence() in
	which case the interface is presented as a forward range of Rows.
	
	This method allows you to deal with very large result sets either a row at a time,
	or by feeding the rows into some suitable container such as a linked list.
	
	Returns: A Row object.
	+/
	deprecated("Use Connection.getNextRow() instead.")
	Row getNextRow()
	{
		return _con.getNextRow();
	}

	/++
	Execute a stored function, with any required input variables, and store the
	return value into a D variable.
	
	For this method, no query string is to be provided. The required one is of
	the form "select foo(?, ? ...)". The method generates it and the appropriate
	bindings - in, and out. Chunked transfers are not supported in either
	direction. If you need them, create the parameters separately, then use
	execPreparedResult() to get a one-row, one-column result set.
	
	If it is not possible to convert the column value to the type of target,
	then execFunction will throw. If the result is NULL, that is indicated
	by a false return value, and target is unchanged.
	
	In the interest of performance, this method assumes that the user has the
	equired information about the number and types of IN parameters and the
	type of the output variable. In the same interest, if the method is called
	repeatedly for the same stored function, prepare() is omitted after the first call.
	
	WARNING: This function is not currently unittested.

	Params:
	   T = The type of the variable to receive the return result.
	   U = type tuple of arguments
	   name = The name of the stored function.
	   target = the D variable to receive the stored function return result.
	   args = The list of D variables to act as IN arguments to the stored function.
	
	+/
	deprecated("Use prepareFunction instead")
	bool execFunction(T, U...)(string name, ref T target, U args)
	{
		bool repeatCall = name == _prevFunc;
		enforceEx!MYX(repeatCall || !_prepared.isPrepared, "You must not prepare a statement before calling execFunction");

		if(!repeatCall)
		{
			_prepared = prepareFunction(_con, name, U.length);
			_prevFunc = name;
		}

		_prepared.setArgs(args);
		ulong ra;
		enforceEx!MYX(_prepared.execQueryImpl2(ra), "The executed query did not produce a result set.");
		Row rr = _con.getNextRow();
		/+enforceEx!MYX(rr._valid, "The result set was empty.");+/
		enforceEx!MYX(rr._values.length == 1, "Result was not a single column.");
		enforceEx!MYX(typeid(target).toString() == rr._values[0].type.toString(),
						"Target type and column type are not compatible.");
		if (!rr.isNull(0))
			target = rr._values[0].get!(T);
		// If there were more rows, flush them away
		// Question: Should I check in purgeResult and throw if there were - it's very inefficient to
		// allow sloppy SQL that does not ensure just one row!
		_con.purgeResult();
		return !rr.isNull(0);
	}

	/++
	Execute a stored procedure, with any required input variables.
	
	For this method, no query string is to be provided. The required one is
	of the form "call proc(?, ? ...)". The method generates it and the
	appropriate in bindings. Chunked transfers are not supported. If you
	need them, create the parameters separately, then use execPrepared() or
	execPreparedResult().
	
	In the interest of performance, this method assumes that the user has
	the required information about the number and types of IN parameters.
	In the same interest, if the method is called repeatedly for the same
	stored function, prepare() and other redundant operations are omitted
	after the first call.
	
	OUT parameters are not currently supported. It should generally be
	possible with MySQL to present them as a result set.
	
	WARNING: This function is not currently unittested.

	Params:
		T = Type tuple
		name = The name of the stored procedure.
		args = Tuple of args
	Returns: True if the SP created a result set.
	+/
	deprecated("Use prepareProcedure instead")
	bool execProcedure(T...)(string name, ref T args)
	{
		bool repeatCall = name == _prevFunc;
		enforceEx!MYX(repeatCall || !_prepared.isPrepared, "You must not prepare a statement before calling execProcedure");

		if(!repeatCall)
		{
			_prepared = prepareProcedure(_con, name, T.length);
			_prevFunc = name;
		}

		_prepared.setArgs(args);
		ulong ra;
		return _prepared.execQueryImpl2(ra);
	}

	/// After a command that inserted a row into a table with an auto-increment
	/// ID column, this method allows you to retrieve the last insert ID.
	deprecated("Use Connection.lastInsertID instead")
	@property ulong lastInsertID() pure const nothrow { return _con.lastInsertID; }

	/// Gets the number of parameters in this Command
	deprecated("Use Prepared.numArgs instead")
	@property ushort numParams() pure const nothrow
	{
		return _prepared.numArgs;
	}

	/// Gets whether rows are pending
	deprecated("Use Connection.rowsPending instead")
	@property bool rowsPending() pure const nothrow { return _con.rowsPending; }

	/// Gets the result header's field descriptions.
	deprecated("Use Connection.resultFieldDescriptions instead")
	@property FieldDescription[] resultFieldDescriptions() pure { return _con.resultFieldDescriptions; }

	/// Gets the prepared header's field descriptions.
	deprecated("Use Prepared.preparedFieldDescriptions instead")
	@property FieldDescription[] preparedFieldDescriptions() pure { return _prepared._psh.fieldDescriptions; }

	/// Gets the prepared header's param descriptions.
	deprecated("Use Prepared.preparedParamDescriptions instead")
	@property ParamDescription[] preparedParamDescriptions() pure { return _prepared._psh.paramDescriptions; }
}
