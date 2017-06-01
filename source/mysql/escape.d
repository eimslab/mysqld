/// Escape special characters in MySQL strings.
module mysql.escape;


/++
Simple escape function for dangerous SQL characters

Params:
	input = string to escape
	buffer = buffer to use for the output
+/
void mysql_escape ( Buffer, Input ) ( Input input, Buffer buffer )
{
	import std.string : translate;

	immutable string[dchar] transTable = [
		'\\' : "\\\\",
		'\'' : "\\'",
		'\0' : "\\0",
		'\n' : "\\n",
		'\r' : "\\r",
		'"'  : "\\\"",
		'\032' : "\\Z"
	];

	translate(input, transTable, null, buffer);
}


/++
Struct to wrap around a string so it can be passed to formattedWrite and be
properly escaped all using the buffer that formattedWrite provides.

Template Params:
	Input = Type of the input
+/
struct MysqlEscape ( Input )
{
	Input input;

	const void toString ( scope void delegate(const(char)[]) sink )
	{
		struct SinkOutputRange
		{
			void put ( const(char)[] t ) { sink(t); }
		}

		SinkOutputRange r;
		mysql_escape(input, r);
	}
}

/++
Helper function to easily construct a escape wrapper struct

Template Params:
	T = type of the input

Params:
	input = input to escape
+/
MysqlEscape!(T) mysqlEscape ( T ) ( T input )
{
	return MysqlEscape!(T)(input);
}

unittest
{
	import std.array : appender;

	auto buf = appender!string();

	import std.format : formattedWrite;

	formattedWrite(buf, "%s, %s, %s, mkay?", 1, 2,
			mysqlEscape("\0, \r, \n, \", \\"));

	assert(buf.data() == `1, 2, \0, \r, \n, \", \\, mkay?`);
}
