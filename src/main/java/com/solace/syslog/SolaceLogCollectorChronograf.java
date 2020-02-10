/**
 * A Syslog Collector for Solace Event Logs
 *
 * @author rlawrence
 *
 * This class collects syslog messages from any solace broker stores them in
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

import java.util.concurrent.TimeUnit;

import org.influxdb.dto.*;

public class SolaceLogCollectorChronograf extends SolaceLogCollectorInflux
{

    protected boolean m_swapHostCols = false;

    public void usage()
    {
        usage("\nUsage: java SolaceLogCollectorChronograf [options]", false);
        System.out.println("  -swapHostCols                     - Swap Host and Hostname columns (use Hostname for Host/VPN, Host for Event Type)");
        System.exit(0);
    }

    public SolaceLogCollectorChronograf()
    {
    }

    public static void main(String[] args) {
        SolaceLogCollectorChronograf col = new SolaceLogCollectorChronograf();
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

    public void newSolaceLogEvent(SyslogParser parser, String host)
    {
	if (m_db != null)
	{
	    try
	    {
		// Add solace event to Influx, use the host field for host + VPN, and hostname field for the event name (or otherway if swapHostCols enabled).

		Point.Builder point = Point.measurement("syslog")
		    .time(parser.getTimestamp().getTime(), TimeUnit.MILLISECONDS)
		    .tag((m_swapHostCols?"hostname":"host"), (parser.getSolaceVPN()!=null?host+"/"+parser.getSolaceVPN():host))
		    .tag((m_swapHostCols?"host":"hostname"), (parser.getSolaceEventNameShort()!=null?parser.getSolaceEventNameShort():parser.getSolaceEventName()))
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
            if (args[i].compareTo("-swapHostCols")==0)
            {
                m_swapHostCols = true;
		return 0;
            }
        }
	return inc;
    }
}
