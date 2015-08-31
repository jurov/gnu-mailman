import os
import sqlite3
import stat

from Mailman import GPGUtils
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg
from Mailman.htmlformat import *
from datetime import datetime

WOTURL="http://www.btcalpha.com/wot/user/"

def process_signatures(mlist, newpatches, newsigs):
    rootdir = mlist.archive_dir()
    conn = db_conn(mlist)
    gh = GPGUtils.GPGHelper(mlist)
    recvd = datetime.utcnow()
    return _process_signatures(conn, gh, rootdir, newpatches, newsigs, recvd)

def _process_signatures(conn, gh, rootdir, newpatches, newsigs, recvd = None):
    db_updated = False
    #filtered new patches from this msg (same structure as newpatches)
    validpatches = []
    #filtered new signatures for any patches (same structure as newsigs + 'phash' patch hash + key )
    validsigs = []
    with conn:
        #find newpatches name
        for sig in newsigs:
            sigfile = sig['file']
            syslog('gpg',"Processing signature attachment %s" % sigfile)
            shash = sig['id']
            sname = sig['name']

            if db_have_sig(conn,shash):
                continue #already seen sig
            phash = None
            try:
                phash = sname.rsplit('_',1)[1] #hash of patch, if any
            except:
                pass
            if phash and len(phash) == 40:
                pfile = db_get_patchfile(conn,phash)
                if pfile:
                    syslog('gpg',"Found signature for patch %s" % phash)
                    keyids = gh.verifyMessage(os.path.join(rootdir,pfile), os.path.join(rootdir,sigfile),
                                              both_are_filenames = True)
                    if len(keyids) > 0:
                        syslog('gpg',"Valid signature from %s" % keyids)
                        if keyids[0].startswith('0x'):
                            key = keyids[0][2:].upper()
                        else:
                            key = keyids[0].upper()
                        db_add_sig(conn, shash, phash, sigfile, key, sig['url'], sig.get('msg'), recvd) #TODO multiple sigs
                        sig['phash'] = phash
                        sig['key'] = key
                        validsigs.append(sig)
                        db_updated = True
                    continue #hash in the name was ok but sig is prolly corrupted, ignore it
            #existing patch not found, check attachments for a new one
            for patch in newpatches:
                pfile = patch['file']
                pname = patch['name']
                phash = patch['id']
                if sname == pname:
                    if db_get_patchfile(conn,phash):
                        break # we saw this patch/signature already
                    syslog('gpg',"Found patch candidate %s" % pfile)
                    keyids = gh.verifyMessage(os.path.join(rootdir,pfile), os.path.join(rootdir,sigfile),
                                              both_are_filenames = True)
                    if len(keyids) > 0:
                        syslog('gpg',"Valid signature from %s" % keyids)
                        if keyids[0].startswith('0x'):
                            key = keyids[0][2:].upper()
                        else:
                            key = keyids[0].upper()
                        db_add_patch(conn, phash, pfile, key, pname, patch['url'], patch.get('msg'), recvd)
                        validpatches.append(patch)
                        db_add_sig(conn, shash, phash, sigfile, key, sig['url'], sig.get('msg'), recvd)
                        sig['phash'] = phash
                        sig['key'] = key
                        validsigs.append(sig)
                        db_updated = True
                    break
        conn.commit()
        #if db_updated:
        #    db_export(conn,rootdir)
    return (validpatches,validsigs)

def db_conn(mlist, override_db = None):
    if override_db is None:
        override_db = os.path.join(mm_cfg.LIST_DATA_DIR,mlist.internal_name(),'turds.sqlite')
    conn = sqlite3.connect(override_db)
    cur = conn.cursor()
    cur.execute("PRAGMA user_version;")
    version = cur.fetchone()[0]
    if version < 1:
        cur.execute("CREATE TABLE IF NOT EXISTS Patches (phash text primary key, pfilename text, submitter text, msglink text) ")
        cur.execute("CREATE TABLE IF NOT EXISTS Sigs (shash text primary key, phash text references Patches, sigfilename text, keyid text, msglink text) ")
    if version < 2:
        cur.execute("ALTER TABLE Patches ADD COLUMN name text")
    if version < 3:
        cur.execute("ALTER TABLE Patches ADD COLUMN plink text")
        cur.execute("ALTER TABLE Sigs ADD COLUMN siglink text")
    if version < 4:
        cur.execute("ALTER TABLE Patches ADD COLUMN released text")
        cur.execute("ALTER TABLE Patches ADD COLUMN baseline text")
    if version < 5:
        cur.execute("ALTER TABLE Patches ADD COLUMN received text")
        cur.execute("ALTER TABLE Sigs ADD COLUMN received text")
        cur.execute("PRAGMA user_version = 5;")

    conn.commit()
    return conn


def db_get_patchfile(conn, phash):
    cur = conn.cursor()
    cur.execute('select pfilename from Patches where phash = :ph',dict(ph=phash))
    try:
        row = cur.fetchone()
        return row[0]
    except:
        return None

def db_have_sig(conn, shash):
    cur = conn.cursor()
    cur.execute('select 1 from Sigs where shash = :sh',dict(sh=shash))
    try:
        row = cur.fetchone()
        return (row is not None)
    except:
        return False



def db_add_patch(conn, phash, pfile, keyid, name, atturl, msg, received):
    if received:
        received = received.replace(microsecond=0).isoformat()
    cur = conn.cursor()
    cur.execute('insert into Patches(phash, pfilename, submitter, name, plink, msglink, received) '
                'values (:phash, :pfile, :keyid, :name, :atturl, :msg, :received)',
                dict(phash=phash, pfile=pfile, keyid=keyid, name=name, atturl=atturl, msg=msg, received=received))
    return 1 #TODO if succeeded


def db_add_sig(conn, shash, phash, sigfile, keyid, sigurl, msg, received):
    if received:
        received = received.replace(microsecond=0).isoformat()
    cur = conn.cursor()
    cur.execute("insert into Sigs (shash, phash, sigfilename, keyid, siglink, msglink, received) "
                "values (:shash, :phash, :sigfile, :keyid, :sigurl, :msg, :received)",
                dict(shash=shash, phash=phash,sigfile=sigfile, keyid = keyid, sigurl=sigurl, msg=msg, received=received))
    return 1 #TODO if succeeded

def db_export(mlist):
    try:
        rootdir = mlist.archive_dir()
        conn = db_conn(mlist)
        return _db_export(conn,rootdir)
    except Exception,e:
        syslog('gpg','%s' % e)
    return False


def _db_export(conn, archive_dir):
    wot = {}
    cur = conn.cursor()
    try:
        cur.execute('select keyid, nick from WoT')
        wot = dict(cur.fetchall())
    except:
        pass
    cur.execute('select p.phash, p.name, p.plink, p.msglink, p.submitter, s.keyid, s.msglink, s.siglink, p.released, p.baseline, p.received'
    #                   0           1       2       3           4           5       6           7           8       9           10
                ' from Patches p join Sigs s on s.phash = p.phash order by p.received desc ')
    table = Table(width="100%", border="3")
    table.AddRow([Center(Header(4, "Received patches"))])
    table.AddCellInfo(table.GetCurrentRowIndex(), 0, colspan=6,
                      bgcolor=mm_cfg.WEB_HEADER_COLOR)
    table.AddRow(['Patch', 'Patch name', 'Received UTC', 'Signatures', 'Released in', 'Based on'])
    row = cur.fetchone()
    htmlrow = None
    currentid = None
    sigs = None
    while row is not None:
        (phash,pname,plink,pmsglink, psubmitter, skeyid, smsglink, siglink, preleased, pbaseline, preceived) = row
        if htmlrow is None:
            currentid = phash
            sigs = []
            htmlrow = [Link(plink,phash) if plink else phash,
                      pname, preceived, 'SIGS', preleased, pbaseline]

        signedby = [Link(WOTURL + skeyid,  'WoT ' + skeyid[-8:]),' ',
                 Link(siglink, 'Sig') if siglink else '',' ',
                 Link(smsglink,'Message') if smsglink else '',
                 ]

        if psubmitter == skeyid:
            signedby.append(' (author)')

        nick = wot.get(skeyid)
        if not nick:
            nick = '0x' + skeyid[-8:]

        signedby = (nick, Container(*signedby))
        sigs.append(signedby)

        row = cur.fetchone()
        if row is None or row[0] != currentid:
            htmlrow[3] = DefinitionList(*(sigs))
            table.AddRow(htmlrow)
            htmlrow = None

    tmphtml=os.path.join(archive_dir,'.patches.html.tmp')
    omask = os.umask(002)
    try:
        f = open(tmphtml,'w')
        with f:
            f.write('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">\n<html><body>')
            f.write(table.Format())
            f.write('</body></html>')
        #os.chmod(tmpfilename,stat.S_IRUSR | stat.S_IWUSR| stat.S_IRGRP| stat.S_IWGRP| stat.S_IROTH)
        os.rename(tmphtml, os.path.join(archive_dir,'patches.html'))
    finally:
        os.umask(omask)
    return True

def db_add_archive_info(mlist, msg,  archive_url):
    try:
        sigs = msg.get_params(header='X-Sigs-Received')
        if not sigs:
            return False
        conn = db_conn(mlist)
        with conn:
            c = conn.cursor()
            for (patch,keyids) in sigs:
                keyids = keyids.split('.')
                for keyid in keyids:
                    c.execute("update Sigs set msglink = :msglink where keyid=:keyid and phash=:phash",
                              dict(msglink=archive_url, keyid=keyid, phash=patch))

            patches = msg.get_params(header='X-Patches-Received')
            if patches:
                for (patch,name) in patches:
                    c.execute("update Patches set msglink = :msglink where phash = :phash", dict(msglink=archive_url, phash=patch))
        conn.commit()
        return True
    except Exception,e:
        syslog('gpg','%s' % e)
    return False


