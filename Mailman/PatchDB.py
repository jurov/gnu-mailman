import os
import sqlite3
import stat

from Mailman import GPGUtils
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg
from Mailman.htmlformat import *


def process_signatures(mlist, newpatches, newsigs):
    rootdir = mlist.archive_dir()
    db_updated = False
    conn = db_conn(mlist)
    #filtered new patches from this msg (same structure as newpatches)
    validpatches = []
    #filtered new signatures for any patches (same structure as newsigs + 'phash' patch hash + key )
    validsigs = []
    with conn:
        gh = GPGUtils.GPGHelper(mlist)
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
                        db_add_sig(conn, shash, phash, sigfile, key, sig['url']) #TODO multiple sigs
                        validsigs.append({phash:key})
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
                        db_add_patch(conn, phash, pfile, key, pname, patch['url'])
                        validpatches.append(patch)
                        db_add_sig(conn, shash, phash, sigfile, key, sig['url'])
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
        cur.execute("PRAGMA user_version = 3;")

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



def db_add_patch(conn, phash, pfile, keyid, name, atturl):
    cur = conn.cursor()
    cur.execute('insert into Patches(phash, pfilename, submitter, name, plink) values (:phash, :pfile, :keyid, :name, :atturl)',
                dict(phash=phash, pfile=pfile, keyid=keyid, name=name, atturl=atturl))
    return 1 #TODO if succeeded


def db_add_sig(conn, shash, phash, sigfile, keyid, sigurl):
    cur = conn.cursor()
    cur.execute("insert into Sigs (shash, phash, sigfilename, keyid, siglink) values (:shash, :phash, :sigfile, :keyid, :sigurl)",
                dict(shash=shash, phash=phash,sigfile=sigfile, keyid = keyid, sigurl=sigurl))
    return 1 #TODO if succeeded

def db_export(mlist):
    rootdir = mlist.archive_dir()
    conn = db_conn(mlist)
    return _db_export(conn,rootdir)

def _db_export(conn, archive_dir):
    cur = conn.cursor()
    cur.execute('select p.phash, p.name, p.plink, p.msglink, p.submitter, s.keyid, s.msglink from Patches p join Sigs s order by p.phash')
    #                   0           1       2       3           4           5       6
    table = Table(width="100%")
    table.AddRow([Center(Header(4, "Received patches"))])
    table.AddCellInfo(table.GetCurrentRowIndex(), 0, colspan=4,
                      bgcolor=mm_cfg.WEB_HEADER_COLOR)
    table.AddRow(['Patch ID', 'Patch name', 'Submitted by', 'Signed by'])
    row = cur.fetchone()
    htmlrow = None
    currentid = None
    while row is not None:
        if htmlrow is None:
            currentid = row[0]
            htmlrow = [Link(row[2],row[0]) if row[2] else row[0],
                      row[1],
                      Link(row[3],row[4]) if row[3] else row[4],[]]
        if row[4] != row[5]:
            htmlrow[3].append(Link(row[6],row[5]) if row[6] else row[5])
        row = cur.fetchone()
        if row is None or row[0] != currentid:
            htmlrow[3] = UnorderedList(*tuple(htmlrow[3]))
            table.AddRow(htmlrow)
            htmlrow = None

    tmpfilename=os.path.join(archive_dir,'.patches.html.tmp')
    omask = os.umask(002)
    try:
        f = open(tmpfilename,'w')
        with f:
            f.write('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">\n<html><body>')
            f.write(table.Format())
            f.write('</body></html>')
        #os.chmod(tmpfilename,stat.S_IRUSR | stat.S_IWUSR| stat.S_IRGRP| stat.S_IWGRP| stat.S_IROTH)
        os.rename(tmpfilename, os.path.join(archive_dir,'patches.html'))
    finally:
        os.umask(omask)

def db_add_archive_info(mlist, msg,  archive_url):
    sigs = msg.get_params(header='X-Sigs-Received')
    if not sigs:
        return
    conn = db_conn(mlist)
    with conn:
        c = conn.cursor()
        for (patch,keyids) in sigs:
            keyids = keyids.split('.')
            for keyid in keyids:
                c.execute("update Sigs set msglink = :msglink where keyid=:keyid and shash=:shash",
                          dict(msglink=archive_url,keyid=keyid, shash=patch))

        patches = msg.get_params(header='X-Patches-Received')
        if patches:
            for (patch,name) in patches:
                c.execute("update Patches set plink = :plink where phash = :phash", dict(plink=archive_url, phash=patch))
        conn.commit()
    return True

