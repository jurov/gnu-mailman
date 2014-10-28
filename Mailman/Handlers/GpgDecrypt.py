# Copyright (C) 2005 by Stefan Schlott <stefan.schlott informatik.uni-ulm.de>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

"""Decrypt the incoming message using the list key

"""

from Mailman import Errors
from Mailman.Logging.Syslog import syslog
from Mailman import mm_cfg
from Mailman import GPGUtils
from Mailman import Utils
from email.Parser import Parser
from email.MIMEText import MIMEText


def isAdministrativeMail(mlist, msg, msgdata):
    result = False
    if msgdata.get('torequest') or msgdata.get('toleave') \
            or msgdata.get('tojoin') or msgdata.get('toconfirm'):
        result = True
    return result

def enforceEncryptPolicy(mlist, msg, msgdata):
    result = True
    if msgdata.get('toowner') or msgdata.get('toleave') \
            or msgdata.get('tojoin') or msgdata.get('toconfirm'):
        result = False
    if msgdata.get('torequest'):
        # This could be more sophisticated:
        # Parse message, enforce if commands containing passwords are used
        # These would be: password, subscribe, unsubscribe, who
        result = False
    return result

def process(mlist, msg, msgdata):   
    #syslog('gpg','GPG decryption module called')
    # Nothing to do when all encryption has been disabled.
    if mlist.encrypt_policy == 0:
        return

    plaintext = None
    ciphertext = None
    sigid = None
    sigmsg = None
    is_pgpmime = False

    # Check: Is inline pgp?
    if msg.get_content_type()=='application/pgp' or msg.get_param('x-action')=='pgp-encrypted':
        ciphertext = msg.get_payload()
        is_pgpmime = False
    # Check: Is pgp/mime?
    if msg.get_content_type()=='multipart/encrypted' and msg.get_param('protocol')=='application/pgp-encrypted':
        if msg.is_multipart():
            for submsg in msg.get_payload():
                if submsg.get_content_type()=='application/octet-stream':
                    is_pgpmime = True
                    ciphertext=submsg.get_payload()
        else:
            ciphertext = msg.get_payload()
    # Some clients send text/plain messages containing PGP-encrypted data :-(
    if not msg.is_multipart() and (ciphertext==None) and \
            (len(msg.get_payload())>10):
        firstline = msg.get_payload().splitlines()[0]
        if firstline=='-----BEGIN PGP MESSAGE-----':
            syslog('gpg','Encrypted message detected, although MIME type is %s',msg.get_content_type())
            is_pgpmime = False
            ciphertext = msg.get_payload()
    # Ciphertext present? Decode
    if ciphertext:
        gh = GPGUtils.GPGHelper(mlist)
        (plaintext,sigid) = gh.decryptMessage(ciphertext)
        if plaintext is None:
            syslog('gpg','Unable to decrypt GPG data')
            raise Errors.RejectMessage, "Unable to decrypt mail!"
    # Check decryption result
    if plaintext:
        # Good signature message
        if (not isAdministrativeMail(mlist,msg,msgdata)):
            if (not sigid is None):
                sigmsg = 'Message had a good signature from sender'
                if mlist.anonymous_list==0 or mlist.anonymous_list=='No':
                    sigmsg += ' (key id %s)'%sigid
            else:
                sigmsg = 'Posting had no valid signature'
        # Check transfer type
        parser = Parser()
        #syslog('gpg','Test: plaintext=%s',plaintext)
        tmpmsg = parser.parsestr(plaintext)
        #syslog('gpg','Test: plaintext is\n%s\n',plaintext)
        #syslog('gpg','Test: Parsed inner message is\n%s\n',tmpmsg.as_string())
        if msg.get_content_type()=='application/pgp':
            msg.set_type("text/plain")
        msg.del_param("x-action")
        for i in ('Content-Type','Content-Disposition','Content-Transfer-Encoding'):
            if tmpmsg.has_key(i):
                if msg.has_key(i):
                    msg.replace_header(i,tmpmsg.get(i))
                else:
                    msg.add_header(i,tmpmsg.get(i))
        #syslog('gpg','Test: Sigline=%s',sigmsg)
        if tmpmsg.is_multipart():
            #syslog('gpg','Test: Multipart')
            msg.set_payload(None)
            for i in tmpmsg.get_payload():
                msg.attach(i)
            if not sigmsg is None:
                sigfooter = MIMEText(sigmsg, 'plain', Utils.GetCharSet(mlist.preferred_language))
                sigfooter['Content-Disposition'] = 'inline'
                msg.attach(sigfooter)
        else:
            #syslog('gpg','Test: Not multipart')
            tmppayload = tmpmsg.get_payload()
            if not sigmsg is None:
                if not tmppayload.endswith('\n'):
                    tmppayload += '\n'
                tmppayload += '-- \n%s\n' % sigmsg
            msg.set_payload(tmppayload)
        if not is_pgpmime:
            mailclient = ''
            if msg.has_key('User-Agent'):
                mailclient = msg.get('User-Agent').lower()
            # Content-Transfer-Encoding and charset are not standardized...
            if mailclient.startswith('mutt'):
                msg.set_param('charset','utf-8')
                if msg.has_key('Content-Transfer-Encoding'):
                    msg.replace_header('Content-Transfer-Encoding','utf-8')
                else:
                    msg.add_header('Content-Transfer-Encoding','utf-8')
            else:
                # Just a wild guess...
                msg.set_param('charset','iso-8859-1')
                if msg.has_key('Content-Transfer-Encoding'):
                    msg.replace_header('Content-Transfer-Encoding','8bit')
                else:
                    msg.add_header('Content-Transfer-Encoding','8bit')

        #syslog('gpg','Test: Message is now\n%s\n',msg.as_string())
        # --- Old Code ---
        #if is_pgpmime:
        #    if tmpmsg.is_multipart():
        #        msg.set_payload(None)
        #        for i in tmpmsg.get_payload():
        #            msg.attach(i)
        #        if not sigid is None:
        #            sigfooter = MIMEText(sigmsg, 'plain', Utils.GetCharSet(mlist.preferred_language))
        #            sigfooter['Content-Disposition'] = 'inline'
        #            msg.attach(sigfooter)
        #    else:
        #        tmppayload = tmpmsg.get_payload()
        #        if not sigid is None:
        #            tmppayload += '\n-- \n%s\n' % sigmsg
        #        msg.set_payload(tmppayload)
        #else:
        #    # Set content header
        #    #if msg.get_content_type()=='application/pgp':
        #    #    msg.set_type("text/plain")
        #    #msg.del_param("x-action")
        #    # Whole decrypted text is content
        #    tmppayload = tmpmsg.get_payload()
        #    if not sigid is None:
        #        tmppayload += '\n-- \n%s\n' % sigmsg
        #    msg.set_payload(tmppayload)
    elif mlist.encrypt_policy==2:
        if enforceEncryptPolicy(mlist,msg,msgdata):
            syslog('gpg','Throwing RejectMessage exception: Message has to be encrypted')
            raise Errors.RejectMessage, "Message has to be encrypted!"
        else:
            syslog('gpg','Accepting unencrypted message')

