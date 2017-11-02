#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import sqlite3
import nmap
from datetime import datetime
from json import load as jsonload


KEY_TYPES = ('RSA', 'DSA', 'ECDSA', 'EdDSA')

APPDIR = os.path.abspath(os.path.dirname(__file__))
CFG_FILE = os.path.join(APPDIR, 'config.json')
DB_FILE = os.path.join(APPDIR, 'db', 'ssh.sqlite')

fp = open(CFG_FILE, 'r')
cfg = jsonload(fp)


def initdb():
    '''Creates the database tables. '''
    dbdir = os.path.dirname(DB_FILE)
    if not os.path.exists(dbdir):
	os.makedirs(dbdir)

    if os.path.exists(DB_FILE):
	#os.remove(DB_FILE)
	return

    conn = sqlite3.connect(DB_FILE)
    db = conn.cursor()
    print 'creating %s database' % DB_FILE

    fp = open(os.path.join(APPDIR, 'schema_ssh.sql'))
    sql = fp.read()
    db.executescript(sql)
    conn.commit()


def querydb(query, args=(), one=False):
    ''' wrap the db query, fetch into one step '''
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    db = conn.cursor()
    cur = db.execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def pingless(tgt):
    if 'ping' in tgt:
        return 0 if tgt['ping'] else 1
    else:
        return 0


def get_host(nm):
    ''' extract the target host from nm scan result.

    when the scan target is ip,:
    {'hostnames': [{'type': '', 'name': ''}], ... } or
    {'hostnames': [{'type': 'PTR', 'name': 'reversedns.example.com'}], ... }

    when the scan target is a hostname:
    {'hostnames': [{'type': 'user', 'name': 'target.example.com'}], ... }

    '''

    for item in nm['hostnames']:
        if item['type'] == 'user':
            return item['name']  # user inputed hostname

    return nm['addresses']['ipv4']  # user inputed ip


def nmscan(tgt):
    print '\nScanning %s port %d' % (tgt['host'], tgt['port'])
    nm = nmap.PortScanner()
    port = tgt['port']
    if pingless(tgt):
        nm.scan(tgt['host'], str(port), arguments='-T4 -Pn -sV --script ssh-hostkey')
    else:
        nm.scan(tgt['host'], str(port), arguments='-T4 -sV --script ssh-hostkey')

    #print nm.command_line()
    res = []
    for h in nm.all_hosts():
        s = nm[h]
        host = get_host(s)
        hostname = s.hostname()
        try:
            hostkeys_str = s['tcp'][port]['script']['ssh-hostkey']
        except KeyError:
            hostkeys_str = ''

        try:
            v = s['tcp'][port]['version']
        except KeyError:
            v = ''

        hostkeys = extract_hostkey(hostkeys_str)
        res.append({'ip': h, 'port': port, 'hostname': hostname, 'host': host,
                    'version': v, 'hostkeys': hostkeys})
    return res


def extract_hostkey(hostkeys_str):
    hostkeys = [t.strip() for t in hostkeys_str.split('\n')]
    keys = {'DSA': '', 'RSA': '', 'ECDSA': '', 'EdDSA': ''}

    for hk in hostkeys:
        if not hk:
            continue

        hk = hk.split()
        k = '%s %s' % (hk[0], hk[1])
        k_type = hk[2]
        tmp = k_type[1:-1]
        keys[tmp] = k

    return keys


SQL_HOST_ID = 'select h_id from ssh_hosts where host=? and port=?'
def get_host_id(host, port):
    res = querydb(SQL_HOST_ID, (host, port), one=True)

    if res:
        return res[0]
    else:
        return -1


def get_last_scan(h_id):
    sql = ('SELECT version,DSA,RSA,ECDSA,EdDSA,id from ssh_scans '
           'WHERE h_id=? ORDER BY lastscan DESC LIMIT 1')
    res = querydb(sql, (h_id,), one=True)
    return res


def print_hostinfo(nmr):
    ''' print out hostkeys for debug '''
    print 'Scan result for %s' % nmr['host']
    print ' - sshd version: %s' % nmr['version']
    for kt in KEY_TYPES:
        if nmr['hostkeys'][kt]:
            print ' - %s %s' % (kt, nmr['hostkeys'][kt])


def check_scan(nmr):
    ''' check nm scan result agains previous record'''

    print_hostinfo(nmr)

    h_id = get_host_id(nmr['host'], nmr['port'])
    rc = {}
    if h_id == -1:
        add_new_host(nmr)
        return rc

    prv_keys = get_last_scan(h_id)
    cur_keys = nmr['hostkeys']
    is_new_version = 0
    is_new_key = 0
    for kt in KEY_TYPES:

        # some ssh server, for example ssh of Dell RAC, may not report
        # all the key types it supports during next scan, we only compare
        # the key types reported to nmap
        if not cur_keys[kt]:
            continue
        if cur_keys[kt] != prv_keys[kt]:
            is_new_key = 1
            break

    if nmr['version'] and prv_keys['version'] != nmr['version']:
        # version changed, may be routine upgrade, but report it anyway
        is_new_version = 1

    if is_new_version or is_new_key:
        add_new_scan_record(h_id, nmr)
        rc['prv_version'] = prv_keys['version']
        rc['cur_version'] = nmr['version']
        rc['prv_keys'] = prv_keys
        rc['cur_keys'] = cur_keys
        rc['host'] = nmr['host']
        rc['port'] = nmr['port']
        #rc['ip'] = nmr['ip']
        #rc['hostname'] = nmr['hostname']
    else:
        update_scan(prv_keys['id'])   # update lastscan time

    return rc


def update_scan(row_id):
    conn = sqlite3.connect(DB_FILE)
    db = conn.cursor()

    now = time.time()
    cur = db.execute('UPDATE ssh_scans SET lastscan=? WHERE id=?',
            (time.time(), row_id))

    conn.commit()


SQL_NEWRCD = ('INSERT into ssh_scans (h_id,version,RSA,DSA,ECDSA,EdDSA,'
              'firstscan,lastscan) VALUES(?,?,?,?,?,?,?,?)')
def add_new_host(nmr):
    conn = sqlite3.connect(DB_FILE)
    db = conn.cursor()
    sql = 'INSERT into ssh_hosts (host,port,ip,hostname) VALUES(?,?,?,?)'
    cur = db.execute(sql, (nmr['host'],nmr['port'],nmr['ip'],nmr['hostname']))

    cur = db.execute(SQL_HOST_ID, (nmr['host'], nmr['port']))
    rv = cur.fetchone()
    h_id = rv[0]

    now = time.time()
    keys = nmr['hostkeys']
    cur = db.execute(SQL_NEWRCD,
        (h_id, nmr['version'], keys['RSA'], keys['DSA'], keys['ECDSA'],
         keys['EdDSA'], now, now))
    conn.commit()


def add_new_scan_record(h_id, nmr):
    conn = sqlite3.connect(DB_FILE)
    db = conn.cursor()

    now = time.time()
    keys = nmr['hostkeys']
    cur = db.execute(SQL_NEWRCD,
        (h_id, nmr['version'], keys['RSA'], keys['DSA'], keys['ECDSA'],
         keys['EdDSA'], now, now))

    conn.commit()


def main():
    initdb()

    bad = []
    i = 1
    for tgt in cfg['hosts']:
        nmrs = nmscan(tgt)
        for nmr in nmrs:
            rc = check_scan(nmr)
            if rc:
                print 'in main, found bad %d' % i
                i += 1
                bad.append(rc)

    print 'total bad = %d' % len(bad)
    msgs = []
    for b in bad:
        msg = '%s:%s has changed:\n' % ( b['host'], b['port'])
        msg += '    Previous Server Version: %s\n' % b['prv_version']
        msg += '     Current Server Version: %s\n' % b['cur_version']
        for kt in KEY_TYPES:
            if kt in b['cur_keys']:
                msg += '    Previous %s Key: %s\n' % (kt, b['prv_keys'][kt])
                msg += '     Current %s Key: %s\n\n' % (kt, b['cur_keys'][kt])
        msg += '-----------------------------------------------------------'

        msgs.append(msg)

    if msgs:
        sendmail('SSH Server version and key monitor report', '\n'.join(msgs))

    slowbeat()


def sendmail(subject, msgbody):
    from smtplib import SMTP_SSL, SMTP
    from email.mime.text import MIMEText
    from email.Header import Header
    from email.Utils import formatdate

    msg = MIMEText(msgbody)
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = cfg['smtp']['from_addr']
    msg['To'] = cfg['smtp']['to_addr']
    msg['Date'] = formatdate()
    msg.set_charset('utf-8')

    conn = SMTP_SSL(cfg['smtp']['server'], cfg['smtp']['port'])
    conn.login(cfg['smtp']['username'], cfg['smtp']['password'])
    conn.sendmail(cfg['smtp']['from_addr'], (cfg['smtp']['to_addr'],),
                  msg.as_string())
    conn.close()
    print 'Successfully sent mail to {0}'.format(cfg['smtp']['to_addr'])


def slowbeat():
    ''' send a message to confirm the crontab and email are working '''
    if datetime.now().isoweekday() == 1:
        subj = 'Slowbeat from ssh-scan '
        msg = ('This is the weekly testing message to '
               'confirm crontab and email are working.\n')

        sendmail(subj, msg)


if __name__ == "__main__":
    main()
