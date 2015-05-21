# Copyright (C) 2005 by Tilburg University, http://www.uvt.nl/.
# Copyright (C) 2005 by Stefan Schlott
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

"""This is a interface to the GnuPGInterface library. It eases the
creation of instances of the interface and handles deadlock problems
using threads. Furthermore, in this way it should be possible to
replace GnuPGInterface with a different one (if ever needed)."""


import re
import os
import tempfile
import threading

from Mailman import Errors
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg
from Mailman.Utils import sha_new
import GnuPGInterface


class AsyncRead(threading.Thread):
    def __init__(self,infile):
        threading.Thread.__init__(self)
        self.infile=infile
        self.data=None
    def run(self):
        self.data = self.infile.read()
        self.infile.close()

class AsyncWrite(threading.Thread):
    def __init__(self,outfile,data):
        threading.Thread.__init__(self)
        self.outfile=outfile
        self.data=data
    def run(self):
        self.outfile.write(self.data)
        self.outfile.close()


class GPGHelper:
    def __init__(self, mlist):
        self.mlist = mlist
        self.gpgdir="%s/%s/gpg" % (mm_cfg.LIST_DATA_DIR,mlist.internal_name())
        self.pubkeyfile="%s/pubring.gpg" % self.gpgdir
        self.seckeyfile="%s/secring.gpg" % self.gpgdir
        self.trustdbfile="%s/trustdb.gpg" % self.gpgdir

    def getGPGObject(self):
        gpg = GnuPGInterface.GnuPG()
        gpg.options.armor = 1
        gpg.options.meta_interactive = 0
        gpg.options.extra_args.append('--no-secmem-warning')
        gpg.options.homedir = self.gpgdir
        gpg.options.quiet = 0
        return gpg
    
    def cleanListKeyring(self):
        success = True
        if not os.path.isdir(self.gpgdir):
            try:
                os.mkdir(self.gpgdir)
                os.chmod(self.gpgdir,((7*8)+7)*8)
            except IOError, (errno, strerror):
                syslog('error','Could not create gpg dir: %s',strerror)
                success = False
        for fname in (self.pubkeyfile,self.seckeyfile,self.trustdbfile):
            if os.path.exists(fname):
                try:
                    os.unlink(fname)
                except:
                    syslog('error','Unable to remove %s',fname)
                    success = False
        return success


    def checkPerms(self):
        success = True
        if os.path.exists(self.gpgdir):
            try:
                os.chmod(self.gpgdir,((7*8)+7)*8)
            except:
                syslog('error','Unable to set mode on %s',self.gpgdir)
                success = False
            for fname in (self.pubkeyfile,self.seckeyfile,self.trustdbfile):
                if os.path.exists(fname):
                    try:
                        os.chmod(fname,((6*8)+6)*8)
                    except:
                        syslog('error','Unable to set mode on %s',fname)
                        success = False
        return success


    def importKey(self,key):
        gpg = self.getGPGObject()
        p = gpg.run(['--import'],create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        p.handles['stdin'].write(key)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        # Ignore date from t_out
        result = t_err.data
        try:
            p.wait()
        except IOError:
            syslog('gpg','Error importing keys: %s' % result)
            return None
        self.checkPerms()
        pre_key_ids= []
        key_ids= []
        for line in result.lower().splitlines():
            g = re.search('key ([0-9a-f]+):',line)
            if g!=None:
                pre_key_ids.append('0x%s' % g.groups()[0])
        for key in pre_key_ids:
            p = gpg.run(['--list-keys',key],create_fhs=['stdin','stdout','stderr'])
            t_out = AsyncRead(p.handles['stdout'])
            t_out.start()
            t_out.join()
            result = t_out.data
            try:
                p.wait()
            except IOError:
                syslog('gpg','Error importing keys: %s' % result)
                return None
            for line in result.lower().splitlines():
                g = re.search('[ps]ub +[0-9a-z]+/([0-9a-f]{8}) ',line)
                if g!=None:
                    key_ids.append('0x%s' % g.groups()[0])
        return key_ids


    def importAllSubscriberKeys(self):
        gpg = self.getGPGObject()
        p = gpg.run(['--import'],create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        for user in self.mlist.getMembers():
            key = self.mlist.getGPGKey(user)
            if key:
                p.handles['stdin'].write(key)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        # Ignore date from t_out
        result = t_err.data
        try:
            p.wait()
        except IOError:
            syslog('gpg','Error importing keys: %s' % result)
            return None
        self.checkPerms()
        key_ids= []
        for line in result.lower().splitlines():
            g = re.search('key ([0-9a-f]+):',line)
            if g!=None:
                key_ids.append('0x%s' % g.groups()[0])
        return key_ids


    def removeKeys(self,keyids):
        gpg = self.getGPGObject()
        params = ['--batch','--yes','--delete-keys']
        for i in keyids:
            params.append(i)
        p = gpg.run(params,create_fhs=['stdin','stdout','stderr'])
        result = p.handles['stderr'].read()
        p.handles['stderr'].close()
        try:
            p.wait()
        except IOError:
            syslog('gpg','Error removing keys: %s' % result)
            return False
        self.checkPerms()
        return True


    def getMailaddrs(self,keyid):
        gpg = self.getGPGObject()
        p = gpg.run(['--list-keys',keyid],create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_out.join()
        result = t_out.data
        try:
            p.wait()
        except IOError:
            syslog('gpg','Error listing keys: %s' % result)
            return None
        mailaddrs = []
        for line in result.lower().splitlines():
            # uid                  Joost van Baal (foo bar) <J.E.vanBaal@uvt.nl>
            g = re.search('uid +[^<]+<([^>]+)>',line)
            if g!=None:
                mailaddrs.append(g.groups()[0])
        return mailaddrs


    def decryptMessage(self,msg):
        gpg = self.getGPGObject()
        plaintext = None
        p = gpg.run(['--decrypt','--no-permission-warning'],
            create_fhs=['stdin','stdout','stderr','status','passphrase'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        t_status = AsyncRead(p.handles['status'])
        t_status.start()
        p.handles['passphrase'].write(self.mlist.gpg_passphrase)
        p.handles['passphrase'].close()
        p.handles['stdin'].write(msg)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        t_status.join()
        plaintext = t_out.data
        status = t_status.data
        result = t_err.data
        try:
            p.wait()
        except IOError:
            if (plaintext==None) or (len(plaintext)==0):
                syslog('gpg',"Error decrypting message: %s",result)
                return (None,None)
            else:
                syslog('gpg',"Return code non-zero, but plaintext received: %s",result)

        # Check signature
        key_ids = []
        for line in status.splitlines():
            # example status output:
            #
            #[GNUPG:] NEED_PASSPHRASE D044CC7F450B4EE8 5F76E17A88C6EDF6 16 0
            #[GNUPG:] GOOD_PASSPHRASE
            #[GNUPG:] BEGIN_DECRYPTION
            #[GNUPG:] PLAINTEXT 62 1113571634 issue
            #[GNUPG:] PLAINTEXT_LENGTH 1914
            #[GNUPG:] SIG_ID H2clD0wU6w1QYPF38D7wAYzyy9s 2005-03-14 1110797362
            #[GNUPG:] GOODSIG 5F76E17A88C6EDF6 Joost van Baal <j.e.vanbaal@uvt.nl>
            #[GNUPG:] VALIDSIG 7177F40B051B57938A0BE2195F76E17A88C6EDF6 2005-03-14 1110797362 0 3 0 17 2 00 7177F40B051B57938A0BE2195F76E17A88C6EDF6
            #[GNUPG:] TRUST_ULTIMATE
            #
            # we are using short keyid to pinpoint keys: last 8 hexbytes of long key id
            g = re.search('^\[GNUPG:\] GOODSIG [0-9A-F]{8}([0-9A-F]{8}) ',line)
            if g!=None:
                key_ids.append('0x%s' % g.groups()[0].lower())

        return (plaintext,key_ids)


    def encryptMessage(self,msg,recipients):
        gpg = self.getGPGObject()
        params = ['--encrypt','--always-trust','--batch','--no-permission-warning']
        for i in recipients:
            params.append('-r')
            params.append(i)
        p = gpg.run(params, create_fhs=['stdin','stdout','stderr'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        p.handles['stdin'].write(msg)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        ciphertext = t_out.data
        result = t_err.data
        try:
            p.wait()
        except IOError:
            syslog('gpg',"Error encrypting message: %s",result)
            return None
        return ciphertext


    def encryptSignMessage(self,msg,recipients):
        gpg = self.getGPGObject()
        params = ['--encrypt','--sign','--always-trust','--batch','--no-permission-warning']
        for i in recipients:
            params.append('-r')
            params.append(i)
        p = gpg.run(params, create_fhs=['stdin','stdout','stderr','passphrase'])
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        p.handles['passphrase'].write(self.mlist.gpg_passphrase)
        p.handles['passphrase'].close()
        p.handles['stdin'].write(msg)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        ciphertext = t_out.data
        result = t_err.data
        try:
            p.wait()
        except IOError:
            syslog('gpg',"Error encrypting message: %s",result)
            return None
        return ciphertext


    def verifyMessage(self,msg,signature,both_are_filenames = False, decrypted_checksum = False):
        gpg = self.getGPGObject()

        sigfilename = None
        if signature:
           # signature is not None but a non-empty string: we are dealing with
           # a detached signature

           # our gpg call will look something like
           #  gpg --verify sigfile - < msg
           # we'll need a tmpfile for signature

           # mkstemp is available in python >= 2.3
           # FIXME check errors
           #
           # fd is the file descriptor returned by os.open (NOT a python
           # file object!) (python-Bugs-922922)
           if both_are_filenames:
               args = [signature, msg]
           else:
               (fd, sigfilename) = tempfile.mkstemp('.GPGUtils')
               os.write(fd, signature)
               os.close(fd)
               args = [sigfilename, '-']

        else:
           # signature == None in case complete signature
           #  no args to gpg call, read from stdin
           args = []

        cmd = '--verify'
        if decrypted_checksum:
           cmd = '--decrypt'
        params = [cmd,'--always-trust','--batch','--no-permission-warning']
        # specify stdout too: we don't want to clutter this proces's stdout
        p = gpg.run(params, args=args, create_fhs=['stdin', 'stdout','stderr','status'])
        # see gnupg/DETAILS in the gnupg package for info on status fd
        t_out = AsyncRead(p.handles['stdout'])
        t_out.start()
        t_err = AsyncRead(p.handles['stderr'])
        t_err.start()
        t_status = AsyncRead(p.handles['status'])
        t_status.start()
        if not both_are_filenames:
            p.handles['stdin'].write(msg)
        p.handles['stdin'].close()
        t_out.join()
        t_err.join()
        t_status.join()
        result = t_err.data
        status = t_status.data
        try:
            p.wait()
        except IOError:
            syslog('gpg',"Error verifying message: %s",result)
            return []

        # clean up tmpfile
        if sigfilename and not both_are_filenames:
            os.remove(sigfilename)  # FIXME check errors

        key_ids = []
        for line in status.splitlines():
            # we are using short keyid to pinpoint keys: last 8 hexbytes of long key id
            # g = re.search('^\[GNUPG:\] GOODSIG [0-9A-F]{8}([0-9A-F]{8}) ',line)
            # no, we want full key fingerprint. the last one seems the right
            g = re.search('^\[GNUPG:\] VALIDSIG .* ([0-9A-F]{40})$',line)
            if g!=None:
                key_ids.append('0x%s' % g.groups()[0].lower())

        if not key_ids:
            syslog('gpg',"No good signature found on message: %s (%s)",status,result)
        else:
            if decrypted_checksum:
                key_ids.insert(0,sha_new(t_out.data).hexdigest())
            syslog('gpg',"Valid signature from key(s) %s found on message",key_ids)
        return key_ids

