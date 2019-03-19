# *Scripts for backup Oracle Databases using Veritas NetBackup*


The script is run from the *Veritas Netbackup*. 

First of all, it is necessary to create a corresponding policy in Netbackup and specify the path to the script into _Backup Selection List_ without any parameters and keys.

To automatically run a backup you need to put the script `backup.py` in the `/opt/openv/netbackup/scripts/` directory.

Script owner - `oralce : oinstall`


Access rights on the file - `r-xr-x---`

The script requires a config file `/etc/backup.conf` owned by `oracle:oinstall` with `rw-rw----` access rights

You can work with configuration file using following startup keys:
- -l (--list) - show the current config as a table
- -a (--add) - add new backup policy
- -r (--remove) - remove backup policy
- -e (--edit) - change parameters for policy

Config options

The configuration file consists of sections, led by a [section]header and followed by name = value entries 

In this case, the partition name is the same as the policy name.

 The section contains the following parameters:

    SID
    threadsCount - Number of threads (the number of Allocate Channel in RMAN). 1 by default
    compression - Adding the string as compressed backupset in RMAN). False by default
    databaseFilesperset - Filesperset for backups. 1 for default
    logsFilesperset - Filesperset for logs. 30 for default.
    backupOnlyLogs - For *-archlog is True, False in the other case.
    resyncCatalog - To do or not resync catalog after backup. True by default
    asTableSpace - Mode in which only encrypted tablespaces are backed up with compression. compression=True are required




