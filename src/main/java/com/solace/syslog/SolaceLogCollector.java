/**
 * A Syslog Collector for Solace Event Logs
 *
 * @author rlawrence
 *
 * This tool collects syslog messages from any solace broker stores them in
 * InfluxDB for visualisation with Chronograf
 *
 * The Chronograf log viewer expects an Influx measurememnt called "syslog" according to the
 * following schema:
 *
 * Tags:
 * 	severity
 * 	host	 - used for host/vpn
 *	hostname - used for the solace event name
 *	appname  - used for the solace event tag
 * 	facility 
 *
 * Fields:
 * 	timestamp
 * 	message
 * 	facility_code
 *	severity_code
 *	procid   - used for the solace event type
 *	
 */

package com.solace.syslog;

import java.util.Vector;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.util.concurrent.TimeUnit;


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

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.InfluxDBIOException;
import org.influxdb.dto.*;
import org.influxdb.impl.InfluxDBResultMapper;

public class SolaceLogCollector
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
 
    protected String m_dbURL = "http://localhost:8086";
    protected String m_username = "admin";
    protected String m_password = "admin";
    protected String m_dbName  =  "solace_log";
    protected String m_rpName  =  "policy30d";
    protected boolean m_rpSet = false;
    protected InfluxDB m_db = null;
    protected boolean m_doAll = false;

    public void usage()
    {
        System.out.println("\nUsage: java SolaceLogCollector [options]");
	System.out.println("");
        System.out.println("   where options are:");
        System.out.println("");
        System.out.println("  -dbURL    <DB URL>		- Infux DB URL (default http://localhost:8086)");
        System.out.println("  -username <Username>		- Influx DB usnername (default admin)");
        System.out.println("  -password	<Password>		- Influx DB password (default admin)");
        System.out.println("  -dbName   <DB Name>		- Influx DB name (default solace_log)");
        System.out.println("  -rpName 	<retention policy> 	- Influx DB retention policy name (if not set creates a policy called policy30d - 30 days)");
        System.out.println("  -addr   	<interface>		- The local interface to bind to receive syslogs (default localhost)");
        System.out.println("  -udpPort  <port>			- The UDP port to listen on for syslog messages, 0 disabes UDP (default 514)");
        System.out.println("  -tcpPort  <port>			- The TCP port to listen on for syslog messages, 0 disabes TCP (default 0)");
        System.out.println("  -maxSev  	<max severity>		- The max severity code to process, any greater severity (ie lower importance) is ignored (default 6 - info)");
        System.out.println("  -all				- Process all syslogs collected, including non-solace events");
        System.out.println("  -debug				- Enable debug trace");
        System.exit(0);
    }

    public SolaceLogCollector()
    {
    }

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

	    // Init InfluxDB
	    try
	    {
		m_db =  InfluxDBFactory.connect(m_dbURL, m_username, m_password);

		if (m_db == null)
		{
		    traceError("init: Failed to connect to Influx DB: "+m_dbURL);
		}

		try
		{
		    Pong response = m_db.ping();
		    if (response.getVersion().equalsIgnoreCase("unknown"))
		    {
			traceError("init: Failed to ping Influx DB server at: "+m_dbURL);
		    } else {
			traceInfo("init: Connected to InfluxDB: "+m_dbURL+" version "+response.getVersion());
		    }
		}
		catch (InfluxDBIOException idbo)
		{
		    traceError("init: Failed to connect to Influx DB: "+idbo);
		}

		if (!m_db.databaseExists(m_dbName))
		{
		    traceInfo("init: Influx DB "+m_dbName+" does not exist, attempting to create it");
		    m_db.createDatabase(m_dbName);		// May fail on older Influx versions
		}

		// Need a retention policy if not preset on command line
		if (!m_rpSet)
		{
		    traceInfo("init: Influx rentention policy not set, creating a policy for 30days");
		    m_db.createRetentionPolicy(m_rpName, m_dbName, "30d", 1, true);
		}
		else
		{
		    traceInfo("init: Influx retention policy set as: "+m_rpName+" this must exist");
		}

		if (m_doAll)
		    traceInfo("init: Pushing All syslogs to Influx DB: "+m_dbName+" at: "+m_dbURL);
		else
		    traceInfo("init: Pushing Solace syslogs to Influx DB: "+m_dbName+" at: "+m_dbURL);

	    }
	    catch(Exception ie)
	    {
		traceError("init: Failed to create Influx client: "+ie.getMessage());
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

    public static void main(String[] args) {
        SolaceLogCollector cs = new SolaceLogCollector();
	try
	{
	    cs.parseModuleArgs(args);
	    cs.init();
	    cs.start();
	}
	catch(Exception ie)
	{
	    cs.traceError("Main: Exception: "+ie.getMessage());
	}
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
		pushSolaceEventToInflux(parser, host);
		return;
	    }
	    else if (m_doAll)
	    {
		pushPlainEventToInflux(parser, host);
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

    public void pushSolaceEventToInflux(SyslogParser parser, String host)
    {
	if (m_db != null)
	{
	    try
	    {
		// Add solace event to Influx, use the hostname field for host + VPN, and appname field for the event name.

		Point.Builder point = Point.measurement("syslog")
		    .time(parser.getTimestamp().getTime(), TimeUnit.MILLISECONDS)
		    .tag("host", (parser.getSolaceVPN()!=null?host+"/"+parser.getSolaceVPN():host))
		    .tag("hostname", (parser.getSolaceEventNameShort()!=null?parser.getSolaceEventNameShort():parser.getSolaceEventName()))
		    .tag("severity", parser.getSeverity())
		    .tag("facility", parser.getFacility())
		    .tag("appname", parser.getTag());

		point.addField("timestamp", parser.getTimestamp().getTime()*1000000); // Influx timestamps are in nanos
		point.addField("message", parser.getMsg());
		point.addField("severity_code", parser.getSeverityCode());
		point.addField("facility_code", parser.getFacilityCode());
		point.addField("procid", parser.getSolaceEventType());

		// Influx should be thread safe!
		m_db.write(m_dbName, m_rpName, point.build());

		traceDebug("pushSolaceEventToInflux: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" tag:"+parser.getTag()+" sev:"+parser.getSeverity()+" event:"+parser.getSolaceEventName()+" msg:"+parser.getMsg());
	    }
	    catch(Exception ie)
	    {
		traceWarning("pushSolaceEventToInflux: Failed to push event to Influx: "+ie.toString());
		traceWarning("pushSolaceEventToInflux: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" sev:"+parser.getSeverity()+" event:"+parser.getSolaceEventName()+" msg:"+parser.getMsg());
		traceWarning("------------------");
	    }
	}
    }

    public void pushPlainEventToInflux(SyslogParser parser, String host)
    {
	if (m_db != null)
	{
	    try
	    {
		// Add plain (non-solace) event to Influx

		Point.Builder point = Point.measurement("syslog")
		    .time(parser.getTimestamp().getTime(), TimeUnit.MILLISECONDS)
		    .tag("hostname", host)
		    .tag("host", host)
		    .tag("severity", parser.getSeverity())
		    .tag("facility", parser.getFacility())
		    .tag("appname", parser.getTag());

		point.addField("timestamp", parser.getTimestamp().getTime()*1000000); // Influx timestamps are in nanos
		point.addField("message", parser.getMsg());
		point.addField("severity_code", parser.getSeverityCode());
		point.addField("facility_code", parser.getFacilityCode());
		if (parser.getProcInfo() != null)
		    point.addField("procid", parser.getProcInfo());

		// Influx should be thread safe!
		m_db.write(m_dbName, m_rpName, point.build());

		traceDebug("pushPlainEventToInflux: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" tag:"+parser.getTag()+" sev:"+parser.getSeverity()+" msg:"+parser.getMsg());
	    }
	    catch(Exception ie)
	    {
		traceWarning("pushPlainEventToInflux: Failed to push event to Influx: "+ie.getMessage());
		traceWarning("pushPlainEventToInflux: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" sev:"+parser.getSeverity()+" msg:"+parser.getMsg());
		traceWarning("------------------");
	    }
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

		/* recv messages */
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

		/* recv connections */
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

		    /* recv messages */
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
    private int convertStringToInt(String value)
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
	int i=0;

        while(i < args.length)
        {
            if (args[i].compareTo("-all")==0)
            {
                m_doAll = true;
		i += 1;
            }
            else
            if (args[i].compareTo("-debug")==0)
            {
                m_debug = true;
		i += 1;
            }
            else
            if (args[i].compareTo("-dbURL")==0)
            {
                if ((i+1) >= args.length) usage();
                m_dbURL = args[i+1];
		i += 2;
            }
            else
            if (args[i].compareTo("-dbName")==0)
            {
                if ((i+1) >= args.length) usage();
                m_dbName = args[i+1];
		i += 2;
            }
            else
            if (args[i].compareTo("-username")==0)
            {
                if ((i+1) >= args.length) usage();
                m_username = args[i+1];
		i += 2;
            }
            else
            if (args[i].compareTo("-password")==0)
            {
                if ((i+1) >= args.length) usage();
                m_password = args[i+1];
		i += 2;
            }
            else
            if (args[i].compareTo("-rpName")==0)
            {
                if ((i+1) >= args.length) usage();
                m_rpName = args[i+1];
		m_rpSet = true;
		i += 2;
            }
            else
            if (args[i].compareTo("-addr")==0)
            {
                if ((i+1) >= args.length) usage();
                m_addr = args[i+1];
		i += 2;
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
		i += 2;
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
		i += 2;
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
		i += 2;
            }
	    else
            {
                usage();
            }
        }
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
