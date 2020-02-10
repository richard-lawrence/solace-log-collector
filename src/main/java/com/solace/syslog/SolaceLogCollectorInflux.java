/**
 * A Syslog Collector for Solace Event Logs
 *
 * @author rlawrence
 *
 * This class collects syslog messages from any solace broker stores them in
 * InfluxDB for visualisation with Grafana
 *
 * Creates an Influx measurememnt called "syslog" according to the following schema:
 *
 * Tags:
 * 	host
 * 	severity
 * 	vpn	  - Solace VPN name
 *	eventName - Solace event name
 * 	eventType - Solace event type (SYSTEM, VPN, CLIENT)
 *
 * Fields:
 * 	message
 *	tag	- Solace tag name
 *	
 */

package com.solace.syslog;

import java.util.concurrent.TimeUnit;

import org.influxdb.InfluxDB;
import org.influxdb.InfluxDBFactory;
import org.influxdb.InfluxDBIOException;
import org.influxdb.dto.*;
import org.influxdb.impl.InfluxDBResultMapper;

public class SolaceLogCollectorInflux extends SolaceLogCollector
{

    protected String m_dbURL = "http://localhost:8086";
    protected String m_username = "admin";
    protected String m_password = "admin";
    protected String m_dbName  =  "solace_log";
    protected String m_rpName  =  "policy30d";
    protected boolean m_rpSet = false;
    protected InfluxDB m_db = null;
 

    public void usage()
    {
        usage("\nUsage: java SolaceLogCollectorInflux [options]", false);
	System.exit(0);
    }

    public void usage(String header, boolean doExit)
    {
 
	super.usage(header, doExit);
        System.out.println("  -dbURL    <DB URL>                - Infux DB URL (default http://localhost:8086)");
        System.out.println("  -username <Username>              - Influx DB username (default admin)");
        System.out.println("  -password <Password>              - Influx DB password (default admin)");
        System.out.println("  -dbName   <DB Name>               - Influx DB name (default solace_log)");
        System.out.println("  -rpName   <retention policy>      - Influx DB retention policy name (if not set creates a policy called policy30d for 30 days)");
    }
 
     public static void main(String[] args)
     {
        SolaceLogCollectorInflux col = new SolaceLogCollectorInflux();
	try
	{
	    col.parseModuleArgs(args);
	    col.init();
	    col.start();
	}
	catch(Exception ie)
	{
	    col.traceError("Main: Exception: "+ie.getMessage());
	}
    }

    public SolaceLogCollectorInflux()
    {
    }

    public void init()
    {
	super.init();

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

    public void newSolaceLogEvent(SyslogParser parser, String host)
    {
	if (m_db != null)
	{
	    try
	    {
		// Add solace event to Influx, prefix message with severity for indicator in Grafana logs panel

		Point.Builder point = Point.measurement("syslog")
		    .time(parser.getTimestamp().getTime(), TimeUnit.MILLISECONDS)
		    .tag("host",host)
		    .tag("vpn",(parser.getSolaceVPN()!=null?parser.getSolaceVPN():""))
		    .tag("eventName", parser.getSolaceEventName())
		    .tag("eventType", parser.getSolaceEventType())
		    .tag("severity", parser.getSeverity());

		point.addField("message", parser.getSeverity()+" "+parser.getLongMsg());
		point.addField("tag", parser.getTag());

		// Influx should be thread safe!
		m_db.write(m_dbName, m_rpName, point.build());

		traceDebug("newSolaceLogEvent: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" tag:"+parser.getTag()+" sev:"+parser.getSeverity()+" event:"+parser.getSolaceEventName()+" msg:"+parser.getMsg());
	    }
	    catch(Exception ie)
	    {
		traceWarning("newSolaceLogEvent: Failed to push event to Influx: "+ie.toString());
		traceWarning("newSolaceLogEvent: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" sev:"+parser.getSeverity()+" event:"+parser.getSolaceEventName()+" msg:"+parser.getMsg());
		traceWarning("------------------");
	    }
	}
    }

    public void newPlainLogEvent(SyslogParser parser, String host)
    {
	if (m_db != null)
	{
	    try
	    {
		// Add plain (non-solace) event to Influx

		Point.Builder point = Point.measurement("syslog")
		    .time(parser.getTimestamp().getTime(), TimeUnit.MILLISECONDS)
		    .tag("host", host)
		    .tag("severity", parser.getSeverity())
		    .tag("facility", parser.getFacility());

		point.addField("message", parser.getMsg());
		point.addField("tag", parser.getTag());
		if (parser.getProcInfo() != null)
		    point.addField("procid", parser.getProcInfo());

		// Influx should be thread safe!
		m_db.write(m_dbName, m_rpName, point.build());

		traceDebug("newPlainLogEvent: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" tag:"+parser.getTag()+" sev:"+parser.getSeverity()+" msg:"+parser.getMsg());
	    }
	    catch(Exception ie)
	    {
		traceWarning("newPlainLogEvent: Failed to push event to Influx: "+ie.getMessage());
		traceWarning("newPlainLogEvent: "+m_dateFormat.format(parser.getTimestamp())+" host:"+host+" sev:"+parser.getSeverity()+" msg:"+parser.getMsg());
		traceWarning("------------------");
	    }
	}
    }

    public int parseModuleArg(String[] args, int i)
    {
	int inc = super.parseModuleArg(args, i);

	if (inc < 0 && i < args.length)
        {
            if (args[i].compareTo("-dbURL")==0)
            {
                if ((i+1) >= args.length) usage();
                m_dbURL = args[i+1];
		return 1;
            }
            else
            if (args[i].compareTo("-dbName")==0)
            {
                if ((i+1) >= args.length) usage();
                m_dbName = args[i+1];
		return 1;
            }
            else
            if (args[i].compareTo("-username")==0)
            {
                if ((i+1) >= args.length) usage();
                m_username = args[i+1];
		return 1;
            }
            else
            if (args[i].compareTo("-password")==0)
            {
                if ((i+1) >= args.length) usage();
                m_password = args[i+1];
		return 1;
            }
            else
            if (args[i].compareTo("-rpName")==0)
            {
                if ((i+1) >= args.length) usage();
                m_rpName = args[i+1];
		m_rpSet = true;
		return 1;
            }
        }
	return inc;
    }
}
