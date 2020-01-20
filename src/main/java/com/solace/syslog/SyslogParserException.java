package com.solace.syslog;

public class SyslogParserException extends Exception {
      public SyslogParserException(String message, int index) { super(message+", at index "+index); }
}

