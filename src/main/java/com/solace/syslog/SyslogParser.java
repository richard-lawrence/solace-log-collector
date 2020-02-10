/**
 * A Syslog message parser.
 *
 * This parser supports standard RFC 3164 (BSD syslog) messages, plus Solace extensions
 * for event type, event name, client name, and VPN name.
 *
 * @author rlawrence
 *
 * Can parse raw syslog messages read from network or line as read from a syslog file.
 * When parsing lines from syslog file there is no standard for logging the message severity, 
 * so this determined by searching the message content for any of the following key words:
 *
 * 	emergency
 * 	alert
 *	critical
 * 	error
 *	warning, warn
 *	notice
 *	informational, info
 *	debug
 *
 * If none is found severity defaults to unknown
 */

package com.solace.syslog;

import java.util.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.io.ByteArrayOutputStream;
import java.util.TimeZone;

public class SyslogParser
{

    protected String m_msg = null;
    protected String m_longMsg = null;
    protected String m_solaceMsg = null;
    protected String m_tag = null;
    protected int m_sevCode = -1;
    protected int m_priority = -1;
    protected String m_host = null;
    protected String m_host2 = null;
    protected String m_pinfo = null;
    protected Date m_timestamp = null;
    protected String m_eventType = null;
    protected String m_eventName = null;
    protected String m_eventNameShort = null;
    protected String m_vpn = null;
    protected String m_clientName = null;
    protected int m_index=0;
    // raw syslog line
    protected String m_line=null;

    public SyslogParser()
    {
    }

    public void parseSyslog(String syslogLine) throws SyslogParserException
    {
	// These fields may be accessed bu the caller after a successful parse
        m_msg = null;
        m_longMsg = null;
        m_solaceMsg = null;
	m_tag = null;
	m_pinfo = null;
        m_sevCode = -1;
        m_priority = -1;
        m_host = null;
        m_host2 = null;
        m_timestamp = null;
        m_eventType = null;
        m_eventName = null;
        m_clientName = null;
        m_vpn = null;

	m_index=0;
	m_line = syslogLine;

	// If we are parsing raw syslog read priority (facility*8 + severity)
	if (peek(true) == '<')
	{
	    expect('<');
	    m_priority = readInt();
	    expect('>');
	}

	m_timestamp = readTimestamp();

	expect(' ');
	skipSpaces();

	m_longMsg = peekLine();

	// NOTE some messages do not contain hostname, so check for tag first
	if (!peekWord().contains(":"))
	{
	    m_host = readWord();

	    expect(' ');
	    skipSpaces();
	}
	// collectors insert IP address before hostname, so for some messages we'll have both
	if (!peekWord().contains(":"))
	{
	    m_host2 = readWord();

	    expect(' ');
	    skipSpaces();
	}

	m_tag = readTag();

	// read additional originating process info enclosed in [] (often contains pid)
	if (peek(true) == '[')
	    m_pinfo = readPinfo();

	expect(':');
	skipSpaces();

	if (peekWord().contains(":"))
	{
	    // Read Solace extensions
	    m_eventType = readTag();

	    expect(':');
	    skipSpaces();

	    // include event name in solace message
	    m_solaceMsg = peekLine();

	    m_eventName = readTag();
	    if (m_eventName.startsWith(m_eventType))
	    {
		m_eventNameShort = m_eventName.substring(m_eventType.length()+1);
	    }

	    expect(':');

	    if (m_eventType.equals("SYSTEM"))
	    {
		skipSpaces();
		expect('-');
		skipSpaces();
		expect('-');
		skipSpaces();
	    }
	    else if (m_eventType.equals("VPN"))
	    {
		skipSpaces();
		m_vpn = readWord();
		skipSpaces();
		expect('-');
		skipSpaces();
	    }
	    else if (m_eventType.equals("CLIENT"))
	    {
		skipSpaces();
		m_vpn = readWord();
		skipSpaces();
		m_clientName = readWord();
		skipSpaces();
	    }

	    m_tag = stripSeverityFromTag(m_tag);
	}

	// read rest of message content
	m_msg = readLine();

    }

    protected String readTag() throws SyslogParserException
    {
	ByteArrayOutputStream ret = new ByteArrayOutputStream(16);
	byte c;
	boolean first=true;

	while ((c = read(true)) != 0 && c != ':' && c != '\r' && c != '\n' && (first || c != '['))
	{
		first = false;
		ret.write(c);
	}

	if (c != 0) unread();

	return ret.toString();
    }

    protected String stripSeverityFromTag(String tag)
    {
	if (tag != null && (tag.endsWith("DEBU") ||
				tag.endsWith("INFO") ||
				tag.endsWith("NOTI") ||
				tag.endsWith("WARN") ||
				tag.endsWith("ERRO") ||
				tag.endsWith("CRIT") ||
				tag.endsWith("ALER") ||
				tag.endsWith("EMER")))
	{

	    return tag.substring(0, tag.length() - 4);
	}
	return tag;
    }


    protected String peekTag() throws SyslogParserException
    {
	ByteArrayOutputStream ret = new ByteArrayOutputStream(16);
	byte c;
	boolean first=true;

	int i = m_index;
	while ((c = read(true)) != 0 && c != ':' && c != '\r' && c != '\n' && (first || c != '['))
	{
		first = false;
		ret.write(c);
	}

	m_index = i;

	return ret.toString();
    }
    
    protected int readInt() throws SyslogParserException
    {
	byte c;
	int ret = 0;

	while (Character.isDigit(c = read(false)))
		ret = ret * 10 + (c - '0');

	if (c != 0) unread();

	return ret;
    }

    protected void expect(char c) throws SyslogParserException
    {
	byte d = read(true);

	if (d != c)
	    throw new SyslogParserException("Unexpected syslog character: " + (char) d, m_index);
    }


    protected void skipSpaces() throws SyslogParserException
    {
	byte c;

	while ((c = read(false)) == ' ')
		continue;

	if (c != 0) unread();
    }

    protected void skipWord() throws SyslogParserException
    {
	byte c;

	do {
		c = read(false);
	} while (c != ' ' && c != 0);

	if (c != 0) unread();
    }

    protected Date readTimestamp() throws SyslogParserException
    {
	if (java.lang.Character.isDigit(peek(true)))
	{
	    /**
	     * Try ISO 8601 timestamp (in the following format: "2008-03-01T13:00:00+01:00")
	     */
	    GregorianCalendar cal = new GregorianCalendar(TimeZone.getTimeZone("UTC"));
	    int y = readInt();
	    expect('-');
	    int m = readInt();
	    expect('-');
	    int d = readInt();
	    expect('T');
	    int hh = readInt();
	    expect(':');
	    int mm = readInt();
	    int ss = 0;
	    int ms = 0;
	    if (peek(true) == ':')
	    {
		expect(':');
		ss = readInt();
		if (peek(true) == '.')
		{
		    expect('.');
		    ms = readInt();
		}
	    }

	    int tzh=0,tzm=0;
	    boolean plus = true;
	    if (peek(true) == '+')
	    {
		expect('+');
		tzh = readInt();
		if (peek(true) == ':')
		{
		    expect(':');
		    tzm = readInt();
		}
	    }
	    else if (peek(true) == '-')
	    {
		expect('-');
		plus = false;
		tzh = readInt();
		if (peek(true) == ':')
		{
		    expect(':');
		    tzm = readInt();
		}
	    }
	    else 
	    {
		expect('Z');
	    }

	    cal.set(Calendar.YEAR, y);
	    cal.set(Calendar.MONTH, m-1);
	    cal.set(Calendar.DAY_OF_MONTH, d);
	    cal.set(Calendar.HOUR_OF_DAY, hh);
	    cal.set(Calendar.MINUTE, mm);
	    cal.set(Calendar.SECOND, ss);
	    cal.set(Calendar.MILLISECOND, ms);

	    if (plus) {
		cal.add(Calendar.HOUR, -tzh);
		cal.add(Calendar.MINUTE, -tzm);
	    } else {
		cal.add(Calendar.HOUR, tzh);
		cal.add(Calendar.MINUTE, tzm);
	    }
	    return cal.getTime();

	}
	else
	{

	    // Assume BSD date and time
	    int m = readMonthAbbreviation();

	    expect(' ');
	    skipSpaces();

	    int d = readInt();

	    expect(' ');
	    skipSpaces();

	    int hh = readInt();

	    expect(':');

	    int mm = readInt();

	    expect(':');

	    int ss = readInt();

	    GregorianCalendar cal = new GregorianCalendar(Locale.ROOT);

	    cal.set(Calendar.MONTH, m);
	    cal.set(Calendar.DAY_OF_MONTH, d);
	    cal.set(Calendar.HOUR_OF_DAY, hh);
	    cal.set(Calendar.MINUTE, mm);
	    cal.set(Calendar.SECOND, ss);
	    return cal.getTime();
	}
    }
    
    protected int readMonthAbbreviation() throws SyslogParserException
    {

	switch (read(true)) {
	case 'A':
		switch (read(true)) {
		case 'p':
			skipWord();
			return Calendar.APRIL;

		case 'u':
			skipWord();
			return Calendar.AUGUST;

		default:
			return -1;
		}

	case 'D':
		skipWord();
		return Calendar.DECEMBER;

	case 'F':
		skipWord();
		return Calendar.FEBRUARY;

	case 'J':

		switch (read(true)) {
		case 'a':
			skipWord();
			return Calendar.JANUARY;

		case 'u':
		    switch (read(true)) {
			case 'n':
			    skipWord();
			    return Calendar.JUNE;

			case 'l':
			    skipWord();
			    return Calendar.JULY;
			default:
			    return -1;
		    }

		default:
			return -1;
		}

	case 'M':
		read(true);

		switch (read(true)) {
		case 'r':
			skipWord();
			return Calendar.MARCH;

		case 'y':
			skipWord();
			return Calendar.MAY;

		default:
			return -1;
		}

	case 'N':
		skipWord();
		return Calendar.NOVEMBER;

	case 'O':
		skipWord();
		return Calendar.OCTOBER;

	case 'S':
		skipWord();
		return Calendar.SEPTEMBER;

	default:
		return -1;
	}
    }
    
    protected String readWord() throws SyslogParserException
    {
	ByteArrayOutputStream ret = new ByteArrayOutputStream(8);
	byte c;

	while ((c = read(true)) != 0  && c != ' ' && c != '\r' && c != '\n')
		ret.write(c);

	if (c != 0) unread();

	return ret.toString();
    }

    protected String peekWord() throws SyslogParserException
    {
	ByteArrayOutputStream ret = new ByteArrayOutputStream(8);
	byte c;

	int i = m_index;
	while ((c = read(true)) != 0  && c != ' ' && c != '\r' && c != '\n')
		ret.write(c);

	m_index = i;

	return ret.toString();
    }

    protected String readPinfo() throws SyslogParserException
    {
	ByteArrayOutputStream ret = new ByteArrayOutputStream(8);
	byte c;

	expect('[');

	while ((c = read(true)) != 0  && c != ']' && c != '\r' && c != '\n')
		ret.write(c);

	return ret.toString();
    }
    
    protected byte peek(boolean checkEof) throws SyslogParserException
    {
	byte c = read(checkEof);

	if (c != 0) unread();

	return c;
    }
    

    protected byte read(boolean checkEof) throws SyslogParserException
    {

	if (checkEof && m_index >= m_line.length())
		throw new SyslogParserException("Unexpected end of syslog line", m_index);

	if (m_index >= m_line.length())
	    return 0;

	return (byte) m_line.charAt(m_index++);
    }
    
    protected void unread() throws SyslogParserException
    {
	m_index--;
	if (m_index < 0)
	    throw new SyslogParserException("Unexpected unread of syslog line", m_index);
    }

    protected String readLine() 
    {
	String s = m_line.substring(m_index);
	m_index = m_line.length();
	return s;
    }
    
    protected String peekLine() 
    {
	String s = m_line.substring(m_index);
	return s;
    }
 
    public int getFacilityCode() 
    {
	if (m_priority >= 0)
	{
	    return m_priority / 8;
	}
	return -1;
    }
    public int getSeverityCode() 
    {
	if (m_sevCode < 0)
	{
	    if (m_priority >= 0)
	    {
		m_sevCode = m_priority % 8;
	    }
	    else
	    {
		if (m_line.indexOf("error", m_index) > 0 || m_line.indexOf("Error", m_index) > 0)
		{
		    m_sevCode=3;
		}
		if (m_line.indexOf("warn", m_index) > 0 || m_line.indexOf("Warn", m_index) > 0)
		{
		    m_sevCode=4;
		}
		if (m_line.indexOf("notice", m_index) > 0 || m_line.indexOf("Notice", m_index) > 0)
		{
		    m_sevCode=5;
		}
		if (m_line.indexOf("info", m_index) > 0 || m_line.indexOf("Info", m_index) > 0)
		{
		    m_sevCode=6;
		}
		if (m_line.indexOf("emerg", m_index) > 0 || m_line.indexOf("Emerg", m_index) > 0)
		{
		    m_sevCode=0;
		}
		if (m_line.indexOf("alert", m_index) > 0 || m_line.indexOf("Alert", m_index) > 0)
		{
		    m_sevCode=1;
		}
		if (m_line.indexOf("crit", m_index) > 0 || m_line.indexOf("Crit", m_index) > 0)
		{
		    m_sevCode=2;
		}
		if (m_line.indexOf("debug", m_index) > 0 || m_line.indexOf("Debug", m_index) > 0)
		{
		    m_sevCode=7;
		}
	    }
	}

	return m_sevCode;
    }

    public String getSeverity() 
    {
	switch (getSeverityCode())
	{
	    case 0:	return "emerg";
	    case 1:	return "alert";
	    case 2: 	return "crit";
	    case 3: 	return "error";
	    case 4:	return "warning";
	    case 5:	return "notice";
	    case 6:	return "info"; 
	    case 7:	return "debug"; 
	    default:
		return "unknown";
	    }
    }

    public enum Facility {
	kern,
	user,
	mail,
	daemon,
	auth,
	syslog,
	lpr,
	news,
	uucp,
	cron,
	authpriv,
	ftp,
	ntp,
	audit,
	alert,
	clock,
	local0,
	local1,
	local2,
	local3,
	local4,
	local5,
	local6,
	local7
    }
    
    public String getFacility() 
    {
	int f = getFacilityCode();

	if (f >= 0 && f < Facility.values().length)
	{
	    return Facility.values()[f].name();
	}
	return "unknown";
    }
    public String getTag() 
    {
	return m_tag;
    }
    public String getProcInfo() 
    {
	return m_pinfo;
    }
    public String getHost() 
    {
        return m_host;
    }
    public String getHost2() 
    {
        return m_host2;
    }
    public Date getTimestamp() 
    {
        return m_timestamp;
    }
    public String getMsg() 
    {
        return m_msg;
    }
    public String getLongMsg() 
    {
        return m_longMsg;
    }
    public String getSolaceMsg() 
    {
        return m_solaceMsg;
    }
    public String getSolaceEventType() 
    {
        return m_eventType;
    }
    public String getSolaceEventName() 
    {
        return m_eventName;
    }
    public String getSolaceEventNameShort() 
    {
        return m_eventNameShort;
    }
    public String getSolaceClientName() 
    {
        return m_clientName;
    }
    public String getSolaceVPN() 
    {
        return m_vpn;
    }
}
