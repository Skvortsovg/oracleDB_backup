#!/bin/bash

NAGIOS_OK=0
NAGIOS_WARN=1
NAGIOS_CRIT=2
NAGIOS_UNKNOWN=3


if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "Usage: $0 SID TYPE PERIOD"
  exit $NAGIOS_UNKNOWN
fi

ORACLE_SID="$1"
ORACLE_HOME=$(sed -n '/^ *'"${ORACLE_SID}"'/s/^ *'"${ORACLE_SID}"'\:\(.*\)\:.*$/\1/p' "/var/opt/oracle/oratab")

if [ -z "$ORACLE_HOME" ]; then
  echo "ORACLE_HOME is empty" >&2
  exit $NAGIOS_UNKNOWN
fi

export ORACLE_HOME ORACLE_SID

backup_count=$($ORACLE_HOME/bin/sqlplus -S  ' / as sysdba'  << EOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF

SELECT COUNT(*)
FROM v\$rman_backup_job_details
WHERE 
  start_time     >  systimestamp - INTERVAL '$3' HOUR
  AND input_type =  '$2'
  AND status     IN ('COMPLETED', 'COMPLETED WITH WARNINGS')
/

EOF
)


if [ -z "$backup_count" ]; then
  echo "script returned empty value"
  exit $NAGIOS_UNKNOWN
fi

if [ $backup_count -eq 0 ]; then
  echo "No successful backups during $3h|0"
  exit $NAGIOS_CRIT
fi

echo "Backup count: $backup_count|$backup_count"
exit $NAGIOS_OK

