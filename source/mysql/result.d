module mysql.result;

import std.conv;
import std.exception;
import std.range;
import std.string;
import std.variant;

import mysql.commands;
import mysql.connection;
import mysql.exceptions;
import mysql.protocol.extra_types;
import mysql.protocol.packets;
import mysql.protocol.sockets;

struct Row
{
	import mysql.connection;

package:
	Variant[]   _values; // Temporarily "package" instead of "private"
private:
	bool[]      _nulls;

	private static uint calcBitmapLength(uint fieldCount) pure nothrow
	{
		return (fieldCount+7+2)/8;
	}

	static bool[] consumeNullBitmap(ref ubyte[] packet, uint fieldCount) pure
	{
		uint bitmapLength = calcBitmapLength(fieldCount);
		enforceEx!MYXProtocol(packet.length >= bitmapLength, "Packet too small to hold null bitmap for all fields");
		auto bitmap = packet.consume(bitmapLength);
		return decodeNullBitmap(bitmap, fieldCount);
	}

	// This is to decode the bitmap in a binary result row. First two bits are skipped
	static bool[] decodeNullBitmap(ubyte[] bitmap, uint numFields) pure nothrow
	in
	{
		assert(bitmap.length >= calcBitmapLength(numFields),
				"bitmap not large enough to store all null fields");
	}
	out(result)
	{
		assert(result.length == numFields);
	}
	body
	{
		bool[] nulls;
		nulls.length = numFields;

		// the current byte we are processing for nulls
		ubyte bits = bitmap.front();
		// strip away the first two bits as they are reserved
		bits >>= 2;
		// .. and then we only have 6 bits left to process for this byte
		ubyte bitsLeftInByte = 6;
		foreach(ref isNull; nulls)
		{
			assert(bitsLeftInByte <= 8);
			// processed all bits? fetch new byte
			if (bitsLeftInByte == 0)
			{
				assert(bits == 0, "not all bits are processed!");
				assert(!bitmap.empty, "bits array too short for number of columns");
				bitmap.popFront();
				bits = bitmap.front;
				bitsLeftInByte = 8;
			}
			assert(bitsLeftInByte > 0);
			isNull = (bits & 0b0000_0001) != 0;

			// get ready to process next bit
			bits >>= 1;
			--bitsLeftInByte;
		}
		return nulls;
	}

public:

	this(Connection con, ref ubyte[] packet, ResultSetHeaders rh, bool binary)
	in
	{
		assert(rh.fieldCount <= uint.max);
	}
	body
	{
		scope(failure) con.kill();

		uint fieldCount = cast(uint)rh.fieldCount;
		_values.length = _nulls.length = fieldCount;

		if (binary)
		{
			// There's a null byte header on a binary result sequence, followed by some bytes of bitmap
			// indicating which columns are null
			enforceEx!MYXProtocol(packet.front == 0, "Expected null header byte for binary result row");
			packet.popFront();
			_nulls = consumeNullBitmap(packet, fieldCount);
		}

		foreach (size_t i; 0..fieldCount)
		{
			if(binary && _nulls[i])
				continue;

			SQLValue sqlValue;
			do
			{
				FieldDescription fd = rh[i];
				sqlValue = packet.consumeIfComplete(fd.type, binary, fd.unsigned, fd.charSet);
				// TODO: Support chunk delegate
				if(sqlValue.isIncomplete)
					packet ~= con.getPacket();
			} while(sqlValue.isIncomplete);
			assert(!sqlValue.isIncomplete);

			if(sqlValue.isNull)
			{
				assert(!binary);
				assert(!_nulls[i]);
				_nulls[i] = true;
				_values[i] = null;
			}
			else
			{
				_values[i] = sqlValue.value;
			}
		}
	}

	inout(Variant) opIndex(size_t i) inout
	{
		enforceEx!MYX(_nulls.length > 0, format("Cannot get column index %d. There are no columns", i));
		enforceEx!MYX(i < _nulls.length, format("Cannot get column index %d. The last available index is %d", i, _nulls.length-1));
		return _values[i];
	}

	bool isNull(size_t i) const pure nothrow { return _nulls[i]; }

	@property size_t length() const pure nothrow { return _values.length; }
	alias opDollar = length;

	void toStruct(S)(ref S s) if (is(S == struct))
	{
		foreach (i, dummy; s.tupleof)
		{
			static if(__traits(hasMember, s.tupleof[i], "nullify") &&
					  is(typeof(s.tupleof[i].nullify())) && is(typeof(s.tupleof[i].get)))
			{
				if(!_nulls[i])
				{
					enforceEx!MYX(_values[i].convertsTo!(typeof(s.tupleof[i].get))(),
						"At col "~to!string(i)~" the value is not implicitly convertible to the structure type");
					s.tupleof[i] = _values[i].get!(typeof(s.tupleof[i].get));
				}
				else
					s.tupleof[i].nullify();
			}
			else
			{
				if(!_nulls[i])
				{
					enforceEx!MYX(_values[i].convertsTo!(typeof(s.tupleof[i]))(),
						"At col "~to!string(i)~" the value is not implicitly convertible to the structure type");
					s.tupleof[i] = _values[i].get!(typeof(s.tupleof[i]));
				}
				else
					s.tupleof[i] = typeof(s.tupleof[i]).init;
			}
		}
	}

	void show()
	{
		import std.stdio;

		foreach(Variant v; _values)
			writef("%s, ", v.toString());
		writeln("");
	}
}

struct ResultSet
{
private:
	Row[]          _rows;      // all rows in ResultSet, we store this to be able to revert() to it's original state
	string[]       _colNames;
	Row[]          _curRows;   // current rows in ResultSet
	size_t[string] _colNameIndicies;

package:
	this (Row[] rows, string[] colNames)
	{
		_rows = rows;
		_curRows = _rows[];
		_colNames = colNames;
	}

public:

	@property bool empty() const pure nothrow { return _curRows.length == 0; }

	@property ResultSet save() pure nothrow
	{
		return this;
	}

	@property inout(Row) front() pure inout
	{
		enforceEx!MYX(_curRows.length, "Attempted to get front of an empty ResultSet");
		return _curRows[0];
	}

	@property inout(Row) back() pure inout
	{
		enforceEx!MYX(_curRows.length, "Attempted to get back on an empty ResultSet");
		return _curRows[$-1];
	}

	void popFront() pure
	{
		enforceEx!MYX(_curRows.length, "Attempted to popFront() on an empty ResultSet");
		_curRows = _curRows[1..$];
	}

	void popBack() pure
	{
		enforceEx!MYX(_curRows.length, "Attempted to popBack() on an empty ResultSet");
		_curRows = _curRows[0 .. $-1];
	}

	Row opIndex(size_t i) pure
	{
		enforceEx!MYX(_curRows.length, "Attempted to index into an empty ResultSet range.");
		enforceEx!MYX(i < _curRows.length, "Requested range index out of range");
		return _curRows[i];
	}

	@property size_t length() pure const nothrow { return _curRows.length; }
	alias opDollar = length; ///ditto

	void revert() pure nothrow
	{
		_curRows = _rows[];
	}

	T[string] asAA(T = Variant)()
	{
		enforceEx!MYX(_curRows.length, "Attempted use of empty ResultSet as an associative array.");
		T[string] aa;
		foreach (size_t i, string s; _colNames)
			aa[s] = as!T(front._values[i]);
		return aa;
	}

	@property const(string)[] colNames() const pure nothrow { return _colNames; }

	@property const(size_t[string]) colNameIndicies() pure nothrow
	{
		if(_colNameIndicies is null)
		{
			foreach(index, name; _colNames)
				_colNameIndicies[name] = index;
		}

		return _colNameIndicies;
	}
}

struct ResultRange
{
private:
	Connection       _con;
	ResultSetHeaders _rsh;
	Row              _row; // current row
	string[]         _colNames;
	size_t[string]   _colNameIndicies;
	ulong            _numRowsFetched;
	ulong            _commandID; // So we can keep track of when this is invalidated

	void ensureValid() const pure
	{
		enforceEx!MYXInvalidatedRange(isValid,
			"This ResultRange has been invalidated and can no longer be used.");
	}

package:
	this (Connection con, ResultSetHeaders rsh, string[] colNames)
	{
		_con       = con;
		_rsh       = rsh;
		_colNames  = colNames;
		_commandID = con.lastCommandID;
		popFront();
	}

public:
	~this()
	{
		close();
	}

	@property bool isValid() const pure nothrow
	{
		return _commandID == _con.lastCommandID;
	}

	@property bool empty() const pure nothrow
	{
		if(!isValid)
			return true;

		return !_con._rowsPending;
	}

	@property inout(Row) front() pure inout
	{
		ensureValid();
		enforceEx!MYX(!empty, "Attempted 'front' on exhausted result sequence.");
		return _row;
	}

	void popFront()
	{
		ensureValid();
		enforceEx!MYX(!empty, "Attempted 'popFront' when no more rows available");
		_row = _con.getNextRow();
		_numRowsFetched++;
	}

	T[string] asAA(T = Variant)()
	{
		ensureValid();
		enforceEx!MYX(!empty, "Attempted 'front' on exhausted result sequence.");
		T[string] aa;
		foreach (size_t i, string s; _colNames)
			aa[s] = as!T(_row._values[i]);
		return aa;
	}

	@property const(string)[] colNames() const pure nothrow { return _colNames; }

	@property const(size_t[string]) colNameIndicies() pure nothrow
	{
		if(_colNameIndicies is null)
		{
			foreach(index, name; _colNames)
				_colNameIndicies[name] = index;
		}

		return _colNameIndicies;
	}

	void close()
	out{ assert(!isValid); }
	body
	{
		if(isValid)
			_con.purgeResult();
	}

	@property ulong rowCount() const pure nothrow { return _numRowsFetched; }
}


private T as(T = Variant)(Variant v)
{
	if (is(T == string))
	{
		return asString(v).to!T;
	}
	else
	{
		return v.to!T;
	}
}

private string asString(Variant src)
{
	if (!src.hasValue)
	{
		return string.init;
	}
	
	if (src.convertsTo!string)
	{
		return src.get!string;
	}
	
	import std.datetime;
	
	if (src.type == typeid(DateTime))
	{
		DateTime dt = src.get!DateTime;
		return dt.date().toISOExtString() ~ " " ~ dt.timeOfDay().toISOExtString();
	}
	else
	{
		return std.conv.to!string(src);
	}
}
