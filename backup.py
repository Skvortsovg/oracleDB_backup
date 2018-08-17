#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import logging
import re
import pwd
import datetime
import subprocess
import shutil
import ConfigParser
from collections import namedtuple
import re

CONF_PATH = '/etc/backup.conf'


def rman_logs():
    config = ConfigParser.ConfigParser()
    config.read(CONF_PATH)
    policy = os.environ['NB_ORA_POLICY']
    sid = config.get(policy, 'SID')
    namepart = '{}_archlog'.format(sid) if 'archlog' in policy else sid
    log_file = '/var/tmp/rman_{}.log'.format(namepart)
    open(log_file, 'w').close()
    os.chmod(log_file, 0o666)
    log_file_archive = '/export/home/oracle/rmanlog/rman_{namepart}-{dt}.log'.format(namepart=namepart,
                                                                                     dt=datetime.datetime.today().strftime('%Y.%m.%dT%H-%M-%S'))
    return log_file, log_file_archive

try:
    logging.basicConfig(filename=rman_logs()[0], level=logging.INFO)
    log = logging.getLogger(__name__)
except KeyError:
    pass


def get_oracle_home_path(sid):
    try:
        with open('/var/opt/oracle/oratab', 'r') as oratab_file:
            oratab = oratab_file.read()
        home_path = re.findall(r'.*{sid}:(.*):.*'.format(sid=sid), oratab)[0]
    except IOError:
        log.error("Can't find oratab file.")
        raise SystemExit(1)
    except IndexError:
        log.error("Can't find oraclehome into oratab.")
        raise SystemExit(1)
    except Exception:
        log.error('Error in get_oracle_home_path()')
    else:
        return home_path


def get_tnsadmin_path():
    try:
        with open(os.path.join(os.path.expanduser('~oracle'), '.profile')) as profile_file:
            profile = profile_file.read()
            return re.findall(r'.*TNS_ADMIN=(.*)', profile)[0]
    except Exception:
        try:
            with open(os.path.join(os.path.expanduser('~oracle'), '.bash_profile')) as profile_file:
                profile = profile_file.read()
                return re.findall(r'.*TNS_ADMIN=(.*)', profile)[0]
        except Exception:
            try:
                with open(os.path.join(os.path.expanduser('~oracle'), '.bashrc')) as profile_file:
                    profile = profile_file.read()
                    return re.findall(r'.*TNS_ADMIN=(.*)', profile)[0]
            except:
                log.info("Can't find tns_admin path")
                raise SystemExit(1)



def get_current_user():
    return pwd.getpwuid(os.getuid())[0]


def define_backup_type(onlyLogs):
    env = os.environ
    if env.get('NB_ORA_FULL') == '1':
        backup_type = "INCREMENTAL LEVEL=0"
        shed_name = "Full-Application"
    elif env.get('NB_ORA_INCR') == '1':
        backup_type = "INCREMENTAL LEVEL=1"
        shed_name = "Diff-Application"
    elif env.get('NB_ORA_CINC') == '1':
        backup_type = "INCREMENTAL LEVEL=1 CUMULATIVE"
        shed_name = "Diff-Application"
    else:
        # TODO: delete comment string
        backup_type = "INCREMENTAL LEVEL=0"
        shed_name = "Full-Application"
    if onlyLogs is True:
        shed_name = 'Archive_Logs-Application'
    return backup_type, shed_name


def get_ts(**kwargs):
    cmd = """
ORACLE_HOME={oracle_home}
export ORACLE_HOME
ORACLE_SID={oracle_sid}
export ORACLE_SID
{sqlplus} -S / as sysdba << EOF
SET PAGESIZE 0 LINESIZE 10000 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
select LISTAGG(tablespace_name, ',') WITHIN GROUP (ORDER BY tablespace_name) regular_list from dba_tablespaces where encrypted='NO' and contents <> 'TEMPORARY';
select LISTAGG(tablespace_name, ',') WITHIN GROUP (ORDER BY tablespace_name) encrypted_list from dba_tablespaces where encrypted='YES' and contents <> 'TEMPORARY';
EOF
"""
    sqlplus = os.path.join(kwargs['oracle_home'], 'bin/sqlplus')
    try:
        if get_current_user() == 'root':
            full_out = subprocess.check_output(['su', '-', 'oracle', '-c', cmd.format(oracle_home=kwargs['oracle_home'],
                                                                                                      oracle_sid=kwargs['oracle_sid'],
                                                                                                      sqlplus=sqlplus),
                                                '>>', kwargs['rman_log_file']]).rstrip('\n')
        else:
            full_out = subprocess.check_output(['sh', '-c', cmd.format(oracle_home=kwargs['oracle_home'],
                                                                       oracle_sid=kwargs['oracle_sid'],
                                                                       sqlplus=sqlplus),
                                                '>>', kwargs['rman_log_file']]).rstrip('\n')
        if 'Oracle Corporation' in full_out:
            tss = re.split('\n', full_out, maxsplit=1)[1]
        else:
            tss = re.split('\n\n', full_out, maxsplit=1)[1]
        if '\n' in tss:
            regular_ts, encrypted_ts = tss.split('\n')
        else:
            regular_ts, encrypted_ts = tss, ''
    except Exception as e:
        log.error('Error in getting regular and/or encrypted tablespaces'.format(e))
    else:
        return regular_ts, encrypted_ts


def construct_db_backup_part_cmd(**kwargs):
    env = os.environ
    cmd = []
    if kwargs['asTablespace'] is True:
        log.error('asTablespace is True')
        regular_ts, encrypted_ts = get_ts(**kwargs)
        log.info('regular={}!'.format(regular_ts))
        log.info('encrypted={}!'.format(encrypted_ts))
        if encrypted_ts is '':
            log.error('No encrypted tablespaces.')
            raise SystemExit(1)

    cmd.append('''
# -----------------------------------------------------------------
# RMAN command section
# -----------------------------------------------------------------
RUN {
''')
    for i in range(int(kwargs['threads_count'])):
        cmd.append('''
    ALLOCATE CHANNEL ch{:02d}
    TYPE 'SBT_TAPE';
    '''.format(i))
    cmd.append(
"SEND 'NB_ORA_CLIENT={NB_ORA_CLIENT},NB_ORA_SID={NB_ORA_SID},NB_ORA_POLICY={NB_ORA_POLICY},NB_ORA_SERV={NB_ORA_SERV},NB_ORA_SCHED={NB_ORA_SCHED}';".format(
            NB_ORA_CLIENT=env.get('NB_ORA_CLIENT'),
            NB_ORA_SID=kwargs['oracle_sid'],
            NB_ORA_POLICY=env.get('NB_ORA_POLICY'),
            NB_ORA_SERV='srk-master.mpc.lan',
            NB_ORA_SCHED=kwargs['shed_name']))
    if kwargs['asTablespace'] is False:
        cmd.append('''
BACKUP {compress}
    {BACKUP_TYPE}
    FORMAT 'bk_u%u_s%s_p%p_t%t'
    DATABASE filesperset {dbFilesperset};
'''.format(BACKUP_TYPE=kwargs['backup_type'],
           dbFilesperset=kwargs['dbFilesperset'],
           compress='as compressed backupset' if kwargs['compress'] else ''))
    else:
        cmd.append('''
BACKUP {BACKUP_TYPE} FORMAT 'bk_u%u_s%s_p%p_t%t' tablespace {regular_ts} filesperset {dbFilesperset};
'''.format(BACKUP_TYPE=kwargs['backup_type'],
           regular_ts=regular_ts,
           dbFilesperset=kwargs['dbFilesperset']))
        cmd.append('''
BACKUP {BACKUP_TYPE} FORMAT 'bk_u%u_s%s_p%p_t%t' as compressed backupset tablespace {encrypted_ts} filesperset {dbFilesperset};
'''.format(BACKUP_TYPE=kwargs['backup_type'],
           encrypted_ts=encrypted_ts,
           dbFilesperset=kwargs['dbFilesperset']))
    for i in range(int(kwargs['threads_count'])):
        cmd.append('''RELEASE CHANNEL ch{:02d};'''.format(i))
    return cmd


def construct_logs_backup_part_cmd(**kwargs):
    env = os.environ
    cmd = []
    cmd.append('''
{}
#
# Backup Archived Logs
# For an offline backup, remove the following sql statement
sql 'alter system archive log current';
'''.format('RUN {' if kwargs['only_logs'] is True else ''))
    for i in range(int(kwargs['threads_count'])):
        cmd.append("""
ALLOCATE CHANNEL ch{:02d}
    TYPE 'SBT_TAPE';
""".format(i))
    cmd.append(
"SEND 'NB_ORA_CLIENT={NB_ORA_CLIENT},NB_ORA_SID={NB_ORA_SID},NB_ORA_POLICY={NB_ORA_POLICY},NB_ORA_SERV={NB_ORA_SERV},NB_ORA_SCHED={NB_ORA_SCHED}';".format(
            NB_ORA_CLIENT=env.get('NB_ORA_CLIENT'),
            NB_ORA_SID=kwargs['oracle_sid'],
            NB_ORA_POLICY=env.get('NB_ORA_POLICY'),
            NB_ORA_SERV='srk-master.mpc.lan',
            NB_ORA_SCHED=kwargs['shed_name']))
    cmd.append('''
BACKUP
    FORMAT 'arch_u%u_s%s_p%p_t%t'
    ARCHIVELOG ALL
        filesperset 30;
''')
    for i in range(int(kwargs['threads_count'])):
        cmd.append('''
RELEASE CHANNEL ch{:02d};
'''.format(i))
    return cmd


def construct_controlfile_part_cmd(**kwargs):
    env = os.environ
    cmd = []
    cmd.append('''
#
# Control file backup
''')
    cmd.append('''
ALLOCATE CHANNEL ch00
    TYPE 'SBT_TAPE';
''')
    cmd.append(
"SEND 'NB_ORA_CLIENT={NB_ORA_CLIENT},NB_ORA_SID={NB_ORA_SID},NB_ORA_POLICY={NB_ORA_POLICY},NB_ORA_SERV={NB_ORA_SERV},NB_ORA_SCHED={NB_ORA_SCHED}';".format(
    NB_ORA_CLIENT=env.get('NB_ORA_CLIENT'),
    NB_ORA_SID=kwargs['oracle_sid'],
    NB_ORA_POLICY=env.get('NB_ORA_POLICY'),
    NB_ORA_SERV='srk-master.mpc.lan',
    NB_ORA_SCHED=kwargs['shed_name']))
    cmd.append('''
BACKUP
    FORMAT 'ctrl_u%u_s%s_p%p_t%t'
    CURRENT CONTROLFILE;
BACKUP
    FORMAT 'spfile_u%u_s%s_p%p_t%t'
    SPFILE;
''')
    cmd.append('''
RELEASE CHANNEL ch00;
}
EOF
''')
    return cmd


def constuct_cmd(**kwargs):
    cmd = []
    cmd.append('''
ORACLE_HOME={oracle_home}
export ORACLE_HOME
ORACLE_SID={oracle_sid}
export ORACLE_SID
{rman} target {target_conn_str} nocatalog msglog {rman_log_file} append <<EOF
'''.format(oracle_home=kwargs['oracle_home'],
           oracle_sid=kwargs['oracle_sid'],
           rman=kwargs['rman'],
           target_conn_str=kwargs['target_conn_str'],
           rman_log_file=kwargs['rman_log_file']))
    if kwargs['only_logs'] is False:
         cmd += construct_db_backup_part_cmd(**kwargs)
    cmd += construct_logs_backup_part_cmd(**kwargs)
    cmd += construct_controlfile_part_cmd(**kwargs)
    return ''.join(cmd)


def constuct_resync_cmd(**kwargs):
    cmd = '''
ORACLE_HOME={oracle_home}
export ORACLE_HOME
ORACLE_SID={oracle_sid}
export ORACLE_SID
TNS_ADMIN={tns_admin_path}
export TNS_ADMIN
{rman} target {target_conn_str} catalog=rman_{oracle_sid}/man@rc msglog {rman_log_file} append <<EOF

# -----------------------------------------------------------------
# RMAN command section
# -----------------------------------------------------------------
# The one and only thing we do here
# is resync recovery catalog

resync catalog;

EOF
'''.format(oracle_home=kwargs['oracle_home'],
               oracle_sid=kwargs['oracle_sid'],
               tns_admin_path=get_tnsadmin_path(),
               rman=kwargs['rman'],
               target_conn_str=kwargs['target_conn_str'],
               rman_log_file=kwargs['rman_log_file'])
    return cmd


def get_input(text):
    res = None
    while not res:
        try:
            res = raw_input('%s: ' % text.capitalize())
        except KeyboardInterrupt:
            print
            raise SystemExit(1)
    return res


def get_int(v):
    res = None
    while not res:
        try:
            res = int(raw_input('%s: ' % v.capitalize()))
        except KeyboardInterrupt:
            print
            raise SystemExit(1)
        except ValueError:
            print 'Enter an integer'
    return res


def get_bool(v):
    res = None
    while res is None:
        try:
            res = str2bool(raw_input('%s: ' % v.capitalize()))
        except KeyboardInterrupt:
            print
            raise SystemExit(1)
        except ValueError:
            print 'Enter true or false'
    return res


def conf_manager():
    prog = 'backup_script'
    __version__ = '1.0.0'
    description = 'Script for backup Oracle databases'
    epilog = 'More docs available in http://wiki.mpcompany.local/pages/viewpage.action?pageId=21921794'

    parser = argparse.ArgumentParser(prog=prog,
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description,
                                     epilog=epilog)

    parser.add_argument('-a', '--add',
                        default=False,
                        action='store_true',
                        help='Add new policy')

    parser.add_argument('-rm', '--remove',
                        default=False,
                        action='store_true',
                        help='Remove policy options')

    parser.add_argument('-e', '--edit',
                        default=False,
                        action='store_true',
                        help='Edit backup options')

    parser.add_argument('-l', '--list',
                        default=False,
                        action='store_true',
                        help='Show config')

    opts, args = parser.parse_known_args()
    return opts


def str2bool(s):
    if s.lower() in ['true', '1', 't']:
        return True
    elif s.lower() in ['false', '0', 'f']:
        return False
    else:
        raise ValueError


def get_args():
    config = ConfigParser.ConfigParser()
    config.read(CONF_PATH)

    env = os.environ
    try:
        policy = env['NB_ORA_POLICY']
    except KeyError:
        log.error('NB_ORA_POLICY not found')
        SystemExit(1)
    else:
        if policy not in config.sections():
            log.error("Can't find the right policy")
            SystemExit(1)

        sid = config.get(policy, 'SID')
        threadsCount = config.get(policy, 'ThreadsCount')
        compression = str2bool(config.get(policy, 'Compression'))
        dbFilesperset = config.get(policy, 'DatabaseFilesperset')
        logsFilesperset = config.get(policy, 'LogsFilesperset')
        backupOnlyLogs = str2bool(config.get(policy, 'BackupOnlyLogs'))
        ResyncCatalog = str2bool(config.get(policy, 'ResyncCatalog'))
        asTablespace = str2bool(config.get(policy, 'asTablespace'))
        Arguments = namedtuple('Arguments', 's tc c dbF dbL L r asTs')
        return Arguments(s=sid,
                         tc=threadsCount,
                         c=compression,
                         dbF=dbFilesperset,
                         dbL=logsFilesperset,
                         L=backupOnlyLogs,
                         r=ResyncCatalog,
                         asTs=asTablespace)


def backup():
    args = get_args()
    log.warning(args)
    log_file, log_file_archive = rman_logs()
    log.info('Script {}'.format(sys.argv[0]))
    log.info('==== Started on {} ===='.format(datetime.datetime.today().strftime('%Y.%m.%dT%H-%M-%S')))
    oracle_home = get_oracle_home_path(args.s)
    target_conn_str = '/'
    run_as_user = 'oracle'
    rman = os.path.join(oracle_home, 'bin/rman')
    cuser = get_current_user()
    backup_type, shed_name = define_backup_type(args.L)
    log.info('Performing {shed_name} backup'.format(shed_name=shed_name))
    arguments = {'oracle_home': oracle_home,
                 'oracle_sid': args.s,
                 'rman': rman,
                 'target_conn_str': target_conn_str,
                 'rman_log_file': log_file,
                 'threads_count': args.tc,
                 'shed_name': shed_name,
                 'backup_type': backup_type,
                 'dbFilesperset': args.dbF,
                 'logFilesperset': args.dbL,
                 'only_logs': args.L,
                 'resync': args.r,
                 'compress': args.c,
                 'asTablespace': args.asTs}
    log.info(arguments)
    command = constuct_cmd(**arguments)
    log.info('=== Command ===')
    log.info(command)
    log.info('=== end command ===')

    try:
        if cuser == 'root':
            command = subprocess.check_call(['su', '-', run_as_user, '-c', command, '>>', log_file])
        else:
            command = subprocess.check_call(['sh', '-c', command, '>>', log_file])
    except subprocess.CalledProcessError as e:
        log.error('subprocess.CalledProcessError')
        log.error('returncode={}'.format(e.returncode))
        log.error('command={}'.format(command))
        rstat = e.returncode
    else:
        rstat = 0
    log.info('*** rstat={} ***'.format(rstat))
    if args.r:
        resync_command = constuct_resync_cmd(**arguments)
        log.info('=== ResyncCommand ===')
        log.info(resync_command)
        log.info('=== end ResyncCommand ===')
        try:
            if cuser == 'root':
                command = subprocess.check_call(['su', '-', run_as_user, '-c', resync_command, '>>', log_file])
            else:
                command = subprocess.check_call(['sh', '-c', resync_command, '>>', log_file])
        except subprocess.CalledProcessError as e:
            log.error('RESYNC_COMMAND subprocess.CalledProcessError. returncode= {}'.format(e.returncode))
            rstat_resync = e.returncode
            log.error(e.output)
        else:
            rstat_resync = 0
        log.error(rstat_resync)
    else:
        rstat_resync = 0
    log.info('*** rstat_resync={} ***'.format(rstat_resync))
    if max(rstat, rstat_resync) == 0:
        logmsg = 'ended successfully'
    else:
        logmsg = 'ended in error'

    log.info('Script {}'.format(sys.argv[0]))
    log.info('==== {logmsg} on {date} ===='.format(logmsg=logmsg,
                                                   date=datetime.datetime.today().strftime('%Y.%m.%dT%H-%M-%S')))
    if os.path.exists(log_file):
        shutil.move(log_file, log_file_archive) 
    else:
        log.error("Failed to copy file to archive")
        raise SystemExit(1)

    raise SystemExit(max(rstat, rstat_resync))


def add_policy(config, policy):
    sid = get_input('Enter database SID')
    threadsCount = get_int('Enter threads count')
    compression = get_bool('Is enable compression? False for default. Print True or False')
    if 'archlog' in policy:
        DatabaseFilesperset = 1
        BackupOnlyLogs = True
        asTablespace = False
    else:
        DatabaseFilesperset = get_int('Enter database filesperset. 1 for default')
        BackupOnlyLogs = get_bool('Is save only logs? False for default. Print True or False')
        asTablespace =get_bool('Is backup as tablespace? False for default. Print True or False')
    LogsFilesperset = get_int('Enter logs filesperset. 30 for default')
    ResyncCatalog = get_bool('Is recync catalog? True for default. Print True or False')
    sections = config.sections()
    if policy in sections:
        raise SystemExit('This policy already added')
    config.add_section(policy)
    config.set(policy, 'SID', sid)
    config.set(policy, 'ThreadsCount', threadsCount)
    config.set(policy, 'Compression', compression)
    config.set(policy, 'DatabaseFilesperset', DatabaseFilesperset)
    config.set(policy, 'LogsFilesperset', LogsFilesperset)
    config.set(policy, 'BackupOnlyLogs', BackupOnlyLogs)
    config.set(policy, 'ResyncCatalog', ResyncCatalog)
    config.set(policy, 'asTablespace', asTablespace)

    with open(CONF_PATH, 'wb') as f:
        config.write(f)

def rm_policy(config, policy):
    is_existed = config.remove_section(policy)
    if is_existed:
        print 'Removed'
    else:
        print 'Policy not found'
        return
    with open(CONF_PATH, 'wb') as f:
        config.write(f)


def main():
    opts = conf_manager()
    if os.path.exists(CONF_PATH) is False:
        raise SystemExit('Config file is not exist')
    config = ConfigParser.ConfigParser()
    config.read(CONF_PATH)

    if opts.add is True:
        policy = get_input('Enter policy name')
        add_policy(config, policy)
    elif opts.list is True:
        if not os.path.exists(CONF_PATH):
            log.error('Config file {} not found'.format(CONF_PATH))
            raise SystemExit(1)
        if len(config.sections()) == 0:
            print 'Config file is empty'
            raise SystemExit(0)
        sections = config.sections()
        split_line = '+{0:-^30}+{0:-^20}+{0:-^15}+{0:-^15}+{0:-^15}+{0:-^17}+{0:-^16}+{0:-^17}+{0:-^15}+'.format('')
        print split_line
        print '|{0:^30}| {1:^19}| {2:^14}| {3:^14}| {4:^14}| {5:^16}| {6:^15}| {7:^16}| {8:^14}|'.format(
            'Policy', 'SID', 'threadsCount', 'Compression', 'DBFilesperset', 'LogsFilesperset', 'BackupOnlyLogs', 'ResyncCatalog', 'asTablespace',
        )
        print split_line
        for i in range(len(sections)):
            print '|{policy:<30}| {sid:^19}| {threadsCount:^14}| {compression:^14}| {DBFilesperset:^14}| {LogsFilesperset:^16}| {BackupOnlyLogs:^15}| {ResyncCatalog:^16}| {asTablespace:^14}|'.format(
                policy=sections[i],
                sid=config.get(sections[i], 'SID'),
                threadsCount=config.get(sections[i], 'ThreadsCount'),
                compression=config.get(sections[i], 'Compression'),
                DBFilesperset=config.get(sections[i], 'DatabaseFilesperset'),
                LogsFilesperset=config.get(sections[i], 'LogsFilesperset'),
                BackupOnlyLogs=config.get(sections[i], 'BackupOnlyLogs'),
                ResyncCatalog=config.get(sections[i], 'ResyncCatalog'),
                asTablespace=config.get(sections[i], 'asTablespace')
            )
            print split_line
        raise SystemExit(0)

    elif opts.remove is True:
        policy = get_input('Enter policy name')
        rm_policy(config, policy)
    elif opts.edit is True:
        policy = get_input('Enter policy name')
        rm_policy(config, policy)
        add_policy(config, policy)
    else:
        backup()


if __name__ == '__main__':
    main()
