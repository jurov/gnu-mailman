import re, os
from datetime import datetime
from Mailman import GPGUtils
from Mailman.PatchDB import db_conn,_process_signatures, _db_export

# Process already existing archives. - output of
# cd /srv/mailman/archives/public/btc-dev
# grep -r '<A HREF="http://therealbitcoin.org/ml/btc-dev/attachments/'
# Run as bin/withlist -r parchives.process <listname> <grep_output>

def process(mlist, infile):
    url = mlist.GetBaseArchiveURL()
    conn = db_conn(mlist)
    rootdir = mlist.archive_dir()
    c = conn.cursor()
    gh = GPGUtils.GPGHelper(mlist)
    thismsg = ''
    patches = []
    sigs = []
    with open(infile) as f:
        pat = re.compile('(.*?):URL: &lt;<A HREF="('+ url + '(.*?([^/]+?)((?:_[0-9a-z]{40})+).*?\.([^".]+)))"')
        for line in f:
            res = pat.match(line)
            if not res:
                continue
            (msg, atturl,attpath,attfile,atthashes,attext) = res.groups()
            atthashes = atthashes.split('_')[1:]
            if(thismsg != msg):
                if sigs:
                    res = _process_signatures(conn, gh, rootdir, patches, sigs)
                    print "added patches: %s\n sigs: %s" % res
                thismsg = msg
                patches = []
                sigs = []
            if attext == 'sig':
                c.execute('select sigfilename, msglink, siglink, received from Sigs where shash = :shash', dict(shash=atthashes[0]))
                try:
                    row = c.fetchone()
                except Exception as e:
                    print "%s %s" % (hash, e)
                    continue
                if row:
                    print "Found sig %s, %s, %s" % tuple(row[:3])
                    c.execute('update Sigs set msglink = :link where shash = :shash',
                              dict(link=url + msg, shash = atthashes[0]))
                    if not row[3]:
                        time = os.stat(os.path.join(rootdir, attpath)).st_ctime
                        time = datetime.utcfromtimestamp(time)
                        time = time.replace(microsecond=0).isoformat()
                        c.execute('update Sigs set received = :received where shash = :shash',
                              dict(received=time, shash = atthashes[0]))

                    conn.commit()
                else:
                    print "Not found sig %s, %s, %s" % (atthashes, msg, atturl)
                    sigs.append({'id': atthashes[0], 'name' : attfile, 'file':attpath, 'url': atturl, 'msg' : url + msg})
            else:
                c.execute('select pfilename, msglink, name, received from Patches where phash = :phash', dict(phash=atthashes[0]))
                try:
                    row = c.fetchone()
                except Exception as e:
                    print "%s %s" % (hash, e)
                    continue
                if row:
                    print "Found patch %s, %s, %s" % tuple(row[:3])
                    c.execute("update Patches set msglink = :link where phash = :phash",
                              dict(link=url + msg, phash=atthashes[0]))
                    if not row[3]:
                        time = os.stat(os.path.join(rootdir, attpath)).st_ctime
                        time = datetime.utcfromtimestamp(time)
                        time = time.replace(microsecond=0).isoformat()
                        c.execute('update Patches set received = :received where phash = :phash',
                              dict(received=time, phash = atthashes[0]))

                    conn.commit()

                else:
                    print "Not found patch %s, %s, %s" % (atthashes, msg, atturl)
                    patches.append({'id': atthashes[0], 'name' : attfile, 'file': attpath, 'url': atturl, 'msg' : url + msg})
                #find patch
        conn.commit()
        _db_export(conn, rootdir)

def export(mlist, *arg):
    conn = db_conn(mlist)
    rootdir = mlist.archive_dir()
    _db_export(conn, rootdir)
