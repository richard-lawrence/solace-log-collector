# Example run script to listen for logs on all interfaces with both UDP and TCP port 514 using local InlfuxDB

CLASSPATH=./target/syslog-1.0.jar:./target/dependency/*

sudo java -cp $CLASSPATH  com.solace.syslog.SolaceLogCollector -username admin -password admin -dbURL http://localhost:8086 -addr 0.0.0.0 -all -tcpPort 514
