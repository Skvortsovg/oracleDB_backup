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

more documentation is available [here](http://wiki.mpcompany.local/pages/viewpage.action?pageId=21921794)



