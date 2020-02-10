/**
 * A Syslog Collector for Solace Event Logs
 *
 * @author rlawrence
 *
 * This class collects and parses syslog messages from solace message brokers.
 * The collector receives syslog messages directly from the network and supports both UDP and TCP.
 * Note: Running with root permission may be required to bind to the default UDP port.

 * A subclass is responsible for storing the messages to an appropriate database for visualisation.
 *	
 */

package com.solace.syslog;

import java.util.Date;
import java.text.SimpleDateFormat;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public abstract class SolaceLogCollector
{

    protected 	SimpleDateFormat m_dateFormat = 
            new SimpleDateFormat("EEE MMM dd HH:mm:ss");
    protected boolean m_isRunning=false;
    protected 	UdpReaderThread m_readThread = null;
    protected 	TcpAcceptThread m_acceptThread = null;
    // Ignore everything above 6 (info)
    protected int m_maxSeverity = 6;
    static int	MAX_PACKET_SIZE = 1500;
    protected int m_udpPort = 514;
    protected int m_tcpPort = 0;
    protected String m_addr = "localhost";
    protected DatagramSocket m_udpSocket = null;
    protected ServerSocket m_tcpSocket = null;
    protected boolean m_debug = false;
 
    protected boolean m_doAll = false;

    public void usage(String header, boolean doExit)
    {
	System.out.println(header);
	System.out.println("");
        System.out.println("  where options are:");
        System.out.println("");
        System.out.println("  -addr     <interface>             - The local interface to bind to receive syslogs (default localhost)");
        System.out.println("  -udpPor   <port>                  - The UDP port to listen on for syslog messages, 0 disables UDP (default 514)");
        System.out.println("  -tcpPort  <port>                  - The TCP port to listen on for syslog messages, 0 disables TCP (default 0)");
        System.out.println("  -maxSev   <max severity>          - The max severity code to process, any greater severity (ie lower importance) is ignored (default 6 - info)");
        System.out.println("  -all                              - Process all syslogs collected, including non-solace events");
        System.out.println("  -debug                            - Enable debug trace");
	if (doExit)
	    System.exit(0);
    }

    public abstract void newSolaceLogEvent(SyslogParser parser, String host);

    public abstract void newPlainLogEvent(SyslogParser parser, String host);

    public abstract void usage();
 

    public void init()
    {
        m_isRunning = false;

	if (m_addr != null)
	{
	    try
	    {
		InetAddress iaddr = InetAddress.getByName(m_addr);
		if (iaddr == null)
		{
		    traceError("init: Interface not found: "+m_addr);
		}
		else
		{
		    if (m_udpPort > 0)
		    {
			InetSocketAddress address = new InetSocketAddress(iaddr, m_udpPort);
			//m_udpSocket = new DatagramSocket(m_udpPort);
			m_udpSocket = new DatagramSocket(null);
			traceInfo("init: Binding to UDP socket on: "+m_addr+":"+m_udpPort);
			m_udpSocket.bind(address);
		    }

		    if (m_tcpPort > 0)
		    {
			InetSocketAddress address = new InetSocketAddress(iaddr, m_tcpPort);
			m_tcpSocket = new ServerSocket();
			traceInfo("init: Binding to TCP socket on: "+m_addr+":"+m_tcpPort);
			m_tcpSocket.bind(address);
		    }
		}
	    }
	    catch(Exception e)
	    {
		traceError("init: Exception: "+e.toString());
	    }
	}
    }

    public synchronized void start()
    {
	m_isRunning = false;

	if (m_udpPort > 0)
	{
	    if (m_readThread != null)
		m_readThread.interrupt();

	    m_readThread = new UdpReaderThread();
	    m_readThread.start();
	}
	if (m_tcpPort > 0)
	{
	    if (m_acceptThread != null)
		m_acceptThread.interrupt();

	    m_acceptThread = new TcpAcceptThread();
	    m_acceptThread.start();
	}
    }

    public synchronized void stop()
    {
	m_isRunning = false;
	if (m_readThread != null)
	    m_readThread.interrupt();
	m_readThread = null;
	if (m_acceptThread != null)
	    m_acceptThread.interrupt();
	m_acceptThread = null;
    }

    public void processNewSyslog(SyslogParser parser, String line, String hostAddress)
    {
	try
	{
	    parser.parseSyslog(line);

	    if (parser.getTag().indexOf(' ') >= 0)
	    {
		traceWarning("processNewSyslog: Syslog tag \""+parser.getTag()+"\" contains spaces");
	    }

	    // If no host specified in syslog use source IP Address from UDP packet
	    String host = parser.getHost();
	    if (host == null)
		host = hostAddress;

	    if (host == null)
	    {
		traceWarning("processNewSyslog: No host found in message: "+line);
		host = "Unknown";
	    }
	    if (parser.getSeverityCode() > m_maxSeverity)
	    {
		traceInfo("processNewSyslog: Ignoring severity: "+parser.getSeverity()+"("+parser.getSeverityCode()+") "+m_dateFormat.format(parser.getTimestamp())+" msg: "+parser.getMsg());
		return;
	    }

	    if (parser.getSolaceEventType() != null)
	    {
		newSolaceLogEvent(parser, host);
		return;
	    }
	    else if (m_doAll)
	    {
		newPlainLogEvent(parser, host);
		return;
	    }
	    else
	    {
		traceWarning("processNewSyslog: Unrecognised msg: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" tag:"+parser.getTag()+" sev:"+parser.getSeverity()+" sevCode:"+parser.m_sevCode+" evTyp:"+parser.m_eventType+" evNam:"+parser.getSolaceEventName()+" VPN:"+parser.getSolaceVPN()+" client:"+parser.m_clientName+" msg:"+parser.getMsg());
		traceWarning("------------------");
	    }

	}
	catch (SyslogParserException e)
	{
	    traceWarning("processNewSyslog: ParseException: "+e.getMessage());
	    traceWarning("processNewSyslog: msg: "+line);
	    traceWarning("------------------");
	}
	catch (Exception ex)
	{
	    traceWarning("processNewSyslog: Exception: "+ex.getMessage());
	    traceWarning("processNewSyslog: msg: "+line);
	    traceWarning("------------------");
	}
    }

    class UdpReaderThread extends Thread 
    {

	protected 	SyslogParser parser = new SyslogParser();

    	UdpReaderThread()
    	{
    	}

    	public void run()
    	{
	    m_isRunning = true;
	    if (m_udpSocket != null)
	    {

		byte[] bytes = new byte[MAX_PACKET_SIZE];

		traceDebug("UdpReaderThread: syslog reader thread running..");

		// recv messages
		while (true)
		{
		    try
		    {
			// Receive the next udp message
			DatagramPacket msgPacket = new DatagramPacket(bytes, bytes.length);
			m_udpSocket.receive(msgPacket);
     
			String line = new String(bytes,0,msgPacket.getLength(),"UTF-8");

			processNewSyslog(parser, line, msgPacket.getAddress().getHostAddress());
		    }
		    catch(Exception e)
		    {
			traceError("UdpReaderThread.Exception: "+e.getMessage());
			return;
		    }
		}
		
	    }
    	}
    }
    class TcpAcceptThread extends Thread 
    {
    	TcpAcceptThread()
    	{
    	}

    	public void run()
    	{
	    m_isRunning = true;
	    if (m_tcpSocket != null)
	    {

		traceDebug("TcpAcceptThread: syslog tcp accept thread running..");

		// recv connections
		while (true)
		{
		    try
		    {
			Socket socket = m_tcpSocket.accept();
			new TcpReaderThread(socket).start();

		    } catch (IOException e) {
			traceError("TcpReaderThread.Exception: "+e.getMessage());
			return;
		    }
		}
		
	    }
    	}
    }
    class TcpReaderThread extends Thread 
    {
	Socket socket;
	BufferedReader in;
	protected 	SyslogParser m_parser = new SyslogParser();

    	TcpReaderThread(Socket s)
    	{
	    socket = s;
    	}

    	public void run()
    	{
	    if (socket != null)
	    {
		try
		{
		    in = new BufferedReader(new InputStreamReader(socket.getInputStream()));        
		    String line = null;

		    traceDebug("TcpReaderThread: syslog tcp reader thread running for host "+socket.getInetAddress().getHostAddress());

		    // recv messages
		    while (true)
		    {
			// Receive the next tcp message
			line = in.readLine();

			if (line != null)
			{
			    processNewSyslog(m_parser, line, socket.getInetAddress().getHostAddress());
			}
			else
			{
			    traceDebug("TcpReaderThread: syslog tcp reader thread exiting for host "+socket.getInetAddress().getHostAddress());
			    socket.close();
			    return;
			}
		    }
		    
		}
		catch(Exception e)
		{
		    traceWarning("TcpReaderThread.Exception: "+e.getMessage());
		    return;
		}
	    }
    	}
    }
    public int convertStringToInt(String value)
    {
        if(value != null && !value.equals(""))
	try
	{
	    return Integer.valueOf(value).intValue();
	}
	catch(NumberFormatException e)
	{   
	    traceWarning("convertStringToInt: Exception: "+e.getMessage());
	}
        return 0;
    }

    public void parseModuleArgs(String[] args)
    {
	for (int i = 0; i < args.length; i++)
        {
	    int inc = parseModuleArg(args, i);

	    if (inc < 0)
		usage();
	    else
		i += inc;
	}
 
    }
    public int parseModuleArg(String[] args, int i)
    {

	if (i < args.length)
        {
            if (args[i].compareTo("-all")==0)
            {
                m_doAll = true;
		return 0;
            }
            else
            if (args[i].compareTo("-debug")==0)
            {
                m_debug = true;
		return 0;
            }
            else
            if (args[i].compareTo("-addr")==0)
            {
                if ((i+1) >= args.length) usage();
                m_addr = args[i+1];
		return 1;
            }
            else
            if (args[i].compareTo("-udpPort")==0)
            {
                if ((i+1) >= args.length) usage();
		int p = convertStringToInt(args[i+1]);
                if (p > 0)
		    m_udpPort = p;
		else
		    traceWarning("parseModuleArgs: Invalid UDP port specified: "+args[i+1]+" using: "+m_udpPort);
		return 1;
            }
            else
            if (args[i].compareTo("-tcpPort")==0)
            {
                if ((i+1) >= args.length) usage();
		int p = convertStringToInt(args[i+1]);
                if (p > 0)
		    m_tcpPort = p;
		else
		    traceWarning("parseModuleArgs: Invalid TCP port specified: "+args[i+1]+" using: "+m_tcpPort);
		return 1;
            }
            else
            if (args[i].compareTo("-maxSev")==0)
            {
                if ((i+1) >= args.length) usage();
		int s = convertStringToInt(args[i+1]);
                if (s > 0)
		    m_maxSeverity = s;
		else
		    traceWarning("parseModuleArgs: Invalid maxSev: "+args[i+1]+" using: "+m_maxSeverity);
		return 1;
            }
        }
	return -1;
    }
    public void traceError(String s)
    {
	System.out.println("ERROR "+s);
	System.exit(1);
    }
    public void traceWarning(String s)
    {
	System.out.println("WARNNG "+s);
    }
    public void traceInfo(String s)
    {
	System.out.println(s);
    }
    public void traceDebug(String s)
    {
	if (m_debug)
	{
	    System.out.println("[Debug] "+s);
	}
    }
}
