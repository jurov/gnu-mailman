# Copyright (C) 2005 Tilburg University, http://www.uvt.nl/.
# Author: Joost van Baal
# Inspired by Stefan Schlott's GPGUtils.py
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

"""This is a interface to the openssl command line tool, dealing with
SMIME email messages."""

# It should handle deadlock problems using threads.
# It should be merged with GPGUtils.py and use the pyme GPGME interface.

# It should implement
#   key_ids = sm.verifyMessage(payload, signature)

# import re
import os
# import tempfile
# import threading
import errno

import tempfile

from Mailman import Errors
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg


class SMIMEHelper:
    def __init__(self, mlist):
        self.mlist = mlist

        # /var/lib/mailman/lists/test-secure/gpg is ~/.gnupg/ for list
        # test-secure
        # use /var/lib/mailman/lists/<listname>/smime/{key,cert}.pem

        # FIXME die when these files are not present.  As of 2005-11-28, we behave
        # very bad when these are missing...
        #
        # self.smimedir = "/home/joostvb/smime"
        self.smimedir = "%s/%s/smime" % (mm_cfg.LIST_DATA_DIR,mlist.internal_name())
        self.certfile = "%s/cert.pem" % self.smimedir
        self.keyfile = "%s/key.pem" % self.smimedir
        self.cafile = "%s/ca.pem" % self.smimedir

    def _getSMIMEMemberCertFile(self, member):
        return "%s/%s.cert.pem" % (self.smimedir, member.lower())

    def getSMIMEMemberCertFile(self, member):
        recipfile = self._getSMIMEMemberCertFile(member)

        if not os.access(recipfile,os.F_OK):
            syslog('gpg', "No Member SMIME Certfile '%s' found", recipfile)
            return None

        syslog('gpg', "Using Member SMIME Certfile '%s'", recipfile)
        return recipfile

    def importKey(self, member, key):
        """beware! this routine does _not_ check wether member is a member of the list"""
        recipfile = self._getSMIMEMemberCertFile(member)
        try:
            f = open(recipfile, 'w')
            f.write(key)
            f.close()
            return True
        except IOError:
            syslog('gpg', "Troubles writing S/MIME key for '%s'", member)
            return False

    def decryptMessage(self,msg):
        """Typical invokation: (plaintext,signed) =
           sm.decryptMessage(ciphertext)
           signed is a Bool"""

        # cmd may be a sequence, in which case arguments will be passed
        # directly to the program without shell intervention (as with
        # os.spawnv()). If cmd is a string it will be passed to the shell (as
        # with os.system()).

        # we don't give a password
        # decrypt doesn't need -certfile, doesn't use /etc/ssl/certs/
        cmd = ("openssl", "smime" , "-decrypt", "-recip", self.certfile, "-inkey", self.keyfile)
        #
        # if we _want_ to fork an extra shell, run something like:
        # cmd = "openssl smime -decrypt -recip %s -inkey %s" % (self.certfile, self.keyfile)
        c_in, c_out, c_err = os.popen3(cmd)

        # hrm, we might need to do threading stuff here, like in
        # Mailman/GPGUtils.py
        # for now, the order in which we read and close different file handles
        # _does_ matter!  (does it?)

        c_in.write(msg)
        c_in.close()

        out = c_out.read()
        c_out.close()

        err = c_err.read()
        c_err.close()

        # don't drag along children in zombie status
        # FIXME check return status: actually do something with pid and status.
        # see also Mailman/Utils.py
        pid, status = os.waitpid(-1, os.WNOHANG)

        syslog('gpg',"openssl decrypt stderr: '%s'",err)
        # syslog('gpg',"openssl decrypt stdout: %s",out)

        if out.startswith('Content-Type: multipart/signed; protocol="application/x-pkcs7-signature";'):

            cmd = ("openssl", "smime" , "-verify", "-CAfile", self.cafile)
            c_in, c_out, c_err = os.popen3(cmd)
            c_in.write(out)
            c_in.flush()   # FIXME is this needed?
            c_in.close()
            err = c_err.read()
            plaintext = c_out.read()
            c_out.close()
            c_err.close()

            pid, status = os.waitpid(-1, os.WNOHANG)
            syslog('gpg',"openssl verify stderr: '%s'",err)

            if err.startswith('Verification successful'):
                syslog('gpg',"Valid smime signature found on message")
                return (plaintext,True)
                # return (plaintext,key_ids)  FIXME: bool in key_ids?
            else:
                syslog('gpg',"No good smime signature found on message")
                return (plaintext,False)
        else:
            syslog('gpg',"No good smime signature found on message: no x-pkcs7-signature MIME part in message")
            return (out,False)

    def encryptMessage(self,msg,recipfile):
        """msg: string holding plaintext.  recipfile: .pem file holding
           recipient certificate.  returns ciphertext with leading MIME
           headers"""

        # openssl smime -encrypt %a -outform DER -in %f %c
        # %c One or more certificate IDs.

        # openssl smime -encrypt -in in.txt -from steve@openssl.org \
        #       -to someone@somewhere -subject "Encrypted message" \
        #       -des3 user.pem -out mail.msg


# beware : openssl smime -encrypt from 0.9.7e (like Debian's 0.9.7e-3sarge1) gives us
#  Content-Type: application/x-pkcs7-mime; name="smime.p7m"
# while we need a
#  Content-Type: application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"
# .
# openssl_0.9.8a-4a0.sarge.1 gives us this.

# this works:
#
#  % openssl smime -encrypt ~/.smime/certificates/joostvb-test-banach.crt < /etc/motd.old > ~/tmp/c
#  joostvb@banach:~% openssl smime -decrypt -recip ~/.smime/certificates/joostvb-test-banach.crt -inkey ~/.smime/keys/joostvb-test-banach.key  < ~/tmp/c

        syslog('gpg',"running encryptMessage on '%s'", recipfile)

        # cmd = ("openssl", "smime" , "-encrypt", recipfile)

        # poor man's bfr(1)
        (tmpfd, intmpfilename) = tempfile.mkstemp('.mailman')
        os.write(tmpfd, msg)
        os.close(tmpfd)

        (tmpfd, outtmpfilename) = tempfile.mkstemp('.mailman')
        os.close(tmpfd)

        # "openssl -encrypt" reads and writes at same time.
        # bfr(1) in Debian bfr package would help.
        cmd = "openssl smime -encrypt -in %s %s > %s" % (intmpfilename, recipfile, outtmpfilename)

        syslog('gpg',"encryptMessage: invoking openssl as '%s'", cmd)

        c_in, c_out, c_err = os.popen3(cmd)

        # import popen2
        # c_out, c_in, c_err = popen2.popen3(cmd) # although this is what's suggested in 
        # Python Library Reference - 6.9.2 Flow Control Issues, it doesn't do the trick

        c_in.close()
        err = c_err.read()
        out = c_out.read()
        c_out.close()
        c_err.close()

        # FIXME would (0, os.WNOHANG) be better?
        pid, status = os.waitpid(-1, os.WNOHANG)

        os.remove(intmpfilename)

        tmp = file(outtmpfilename)
        ciphertext = tmp.read()
        tmp.close()
        os.remove(outtmpfilename)

        syslog('gpg',"openssl encrypt stderr: '%s'",err)
        # syslog('gpg',"openssl encrypt stdout: %s",ciphertext)

        return ciphertext


    def encryptSignMessage(self,msg,recipfile):
        """signs as current list"""

        # Sign and encrypt mail:
        # openssl smime -sign -in ml.txt -signer my.pem -text \
        #       | openssl smime -encrypt -out mail.msg \
        #       -from steve@openssl.org -to someone@somewhere \
        #       -subject "Signed and Encrypted message" -des3 user.pem

        # does something like
        # openssl smime -sign -signer ~/.smime/certificates/joostvb+20051121.crt -inkey ~/.smime/keys/joostvb+20051121.key -text < /etc/motd.old | openssl smime -encrypt ~/.smime/certificates/joostvb+20051121.crt > ~/tmp/mail.signed+encrypt
        # uses encryptMessage

        syslog('gpg',"running encryptSignMessage on '%s'", recipfile)

        (tmpfd, intmpfilename) = tempfile.mkstemp('.mailman')
        os.write(tmpfd, msg)
        os.close(tmpfd)

        (tmpfd, outtmpfilename) = tempfile.mkstemp('.mailman')
        os.close(tmpfd)

        (tmpfd, errtmpfilename) = tempfile.mkstemp('.mailman')
        os.close(tmpfd)

        # cmd = ("openssl", "smime", "-sign", "-signer", crtfile, "-inkey", keyfile, "text", "-in", intmpfilename, "-out", outtmpfilename)
        cmd = "openssl smime -sign -signer %s -inkey %s -text < %s > %s 2> %s" % \
          (self.certfile, self.keyfile, intmpfilename, outtmpfilename, errtmpfilename)
        # -sign NEEDS to read from stdin.  "-in" won't work.

        syslog('gpg',"encryptSignMessage: invoking openssl as '%s'", cmd)

        c_in, c_out, c_err = os.popen3(cmd)

        c_in.close()
        err = c_err.read()         # empty
        out = c_out.read()         # empty
        c_out.close()
        c_err.close()

        pid, status = os.waitpid(-1, os.WNOHANG)

        os.remove(intmpfilename)

        o = open(outtmpfilename)
        signeddata = o.read()
        o.close()
        os.remove(outtmpfilename)

        e = open(errtmpfilename)
        err = e.read()
        e.close()
        syslog('gpg',"openssl smime -sign returned '%s'",err)
        os.remove(errtmpfilename)

        # syslog('gpg',"openssl smime -sign returned signed data '%s'", signeddata)

        ciphertext = self.encryptMessage(signeddata, recipfile)
        return ciphertext

    # def verifyMessage(self,msg,signature):
    def verifyMessage(self,msg):
        if msg.is_multipart():
            for submsg in msg.get_payload():
                if submsg.get_content_type()=="application/x-pkcs7-signature":

                    (tmpfd, intmpfilename) = tempfile.mkstemp('.mailman')
                    os.write(tmpfd, msg.as_string())
                    os.close(tmpfd)

                    (tmpfd, outtmpfilename) = tempfile.mkstemp('.mailman')
                    os.close(tmpfd)

                    # specify cmd as a sequence: no shell needed
                    # cmd = ("openssl", "smime", "-verify", "-CAfile", self.cafile)
                    # cmd = "openssl smime -verify -CAfile self.cafile -out %s" % tmpfilename
                    cmd = ("openssl", "smime", "-verify", "-CAfile", self.cafile, "-in", intmpfilename, "-out", outtmpfilename)

                    c_in, c_out, c_err = os.popen3(cmd)

                    c_in.close()
                    err = c_err.read()
                    out = c_out.read()  # empty
                    c_out.close()
                    c_err.close()

                    pid, status = os.waitpid(-1, os.WNOHANG)
                    syslog('gpg',"openssl returned '%s'",err)

                    os.remove(intmpfilename)

                    # holds a copy of payload
                    os.remove(outtmpfilename)

                    if err.startswith('Verification successful'):
                        syslog('gpg',"Valid smime signature found on message")
                        return True
                    else:
                        syslog('gpg',"Invalid smime signature found on message")

        return False
        # return key_ids

