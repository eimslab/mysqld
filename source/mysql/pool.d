module mysql.pool;

import core.thread;
import core.sync.mutex;

import std.datetime;
import std.container.dlist;

import mysql;

final class ConnectionPool
{
    private this(string host, string user, string password, string database, ushort port = 3306,
        uint maxConnections = 50, uint initialConnections = 10, uint incrementalConnections = 5,
        CapabilityFlags caps = defaultClientFlags)
    {
        this._host     = host;
        this._user     = user;
        this._password = password;
        this._database = database;
        this._port     = port;
        this._maxConnections         = maxConnections;
        this._initialConnections     = initialConnections;
        this._incrementalConnections = incrementalConnections;
        this._caps = caps;

        createConnections(initialConnections);
    }

    static ConnectionPool getInstance(string host, string user, string password, string database, ushort port = 3306,
        uint maxConnections = 50, uint initialConnections = 10, uint incrementalConnections = 5,
        CapabilityFlags caps = defaultClientFlags)
    {
        if (_instance is null)
        {
            synchronized(ConnectionPool.classinfo)
            {
                if (_instance is null)
                {
                    _instance = new ConnectionPool(
                        host,
                        user,
                        password,
                        database,
                        port,
                        maxConnections,
                        initialConnections,
                        incrementalConnections,
                        caps
                    );
                }
            }
        }

        return _instance;
    }

    private void createConnections(uint num)
    {
        for (int i; i < num; i++)
        {
            if ((_maxConnections > 0) && (_connections.length >= _maxConnections))
            {
                break;
            }

            _connections ~= new Connection(
                    this._host,
                    this._user,
                    this._password,
                    this._database,
                    this._port,
                    this._caps);
        }
    }

    Connection getConnection()
    {
        synchronized(ConnectionPool.classinfo)
        {
            Connection conn = getFreeConnection();

            if (conn is null)
            {
                Thread.sleep(250.msecs);
                conn = getFreeConnection();
            }

            return conn;
        }
    }

    private Connection getFreeConnection()
    {
        Connection conn = findFreeConnection();

        if (conn is null)
        {
            createConnections(_incrementalConnections);
            conn = findFreeConnection();
        }     

        return conn;
    }

    private Connection findFreeConnection()
    {
        foreach(ref conn; _connections)
        {
            if (!conn.busy)
            {
                conn.busy = true;

                if (!testConnection(conn))
                {
                    conn = new Connection(
                        this._host,
                        this._user,
                        this._password,
                        this._database,
                        this._port,
                        this._caps);
                }

                return conn;
            }
        }

        return null;
    }

    private bool testConnection(Connection conn)
    {
        try
        {
            return !conn.pingServer().error;
        }
        catch (Exception e)
        {
            return false;
        }
    }

    void releaseConnection(Connection conn)
    {
        conn.busy = false;
    }

private:

    __gshared ConnectionPool _instance = null;

    string          _host;
    string          _user;
    string          _password;
    string          _database; 
    ushort          _port;
    CapabilityFlags _caps;

    int             _maxConnections         = 50;
    int             _initialConnections     = 10;
    int             _incrementalConnections = 5;

    Connection[]    _connections;
}
