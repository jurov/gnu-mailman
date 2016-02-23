# Copyright (C) 2001-2015 by the Free Software Foundation, Inc.
# Copyright (C) 2005 by Stefan Schlott <stefan.schlott informatik.uni-ulm.de>
# Copyright (C) 2005 by Tilburg University, http://www.uvt.nl/.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
# USA.

"""Posting moderation filter, if appropriate takes care of decrypting using list key
"""
from os import path as ospath
import re
from email.Parser import Parser
from email.MIMEMessage import MIMEMessage
from email.MIMEText import MIMEText
from email.Utils import parseaddr

from Mailman import mm_cfg
from Mailman import GPGUtils
from Mailman import SMIMEUtils
from Mailman import Utils
from Mailman import Message
from Mailman import Errors
from Mailman.i18n import _
from Mailman.Handlers import Hold
from Mailman.Logging.Syslog import syslog
from Mailman.MailList import MailList



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



def decryptGpg(mlist, msg, msgdata):

    """Returns (encrypted (bool), signed (bool), key_ids), msg is replaced with
       decrypted msg"""

    encrypted = False
    signed = False
    key_ids = []
    plaintext = None
    ciphertext = None
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
                    ciphertext = submsg.get_payload()
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
        (plaintext,key_ids) = gh.decryptMessage(ciphertext)
        if plaintext is None:
            syslog('gpg','Unable to decrypt GPG data')
            raise Errors.RejectMessage, "Unable to decrypt mail!"
        else:
            encrypted = True

    if key_ids:
        signed = True

    if not encrypted:
        return (encrypted, signed, key_ids)

    # Check decryption result

    # Check transfer type
    parser = Parser()
    tmpmsg = parser.parsestr(plaintext)
    if msg.get_content_type()=='application/pgp':
        msg.set_type("text/plain")
    msg.del_param("x-action")
    for i in ('Content-Type','Content-Disposition','Content-Transfer-Encoding'):
        if tmpmsg.has_key(i):
            if msg.has_key(i):
                msg.replace_header(i,tmpmsg.get(i))
            else:
                msg.add_header(i,tmpmsg.get(i))
    if tmpmsg.is_multipart():
        msg.set_payload(None)
        for i in tmpmsg.get_payload():
            msg.attach(i)
    else:
        tmppayload = tmpmsg.get_payload()
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

    if encrypted:
        msg.add_header('X-Mailman-SLS-decrypted', 'Yes')

    return (encrypted, signed, key_ids)


def decryptSmime(mlist, msg, msgdata):
    """Returns (encrypted (bool), signed (bool)), msg is replaced with
       decrypted msg"""

    # FIXME this implementation is _very_ crude.
    # merge some stuff with decryptGpg

    encrypted = False
    signed = False
    plaintext = None
    ciphertext = None

    if msg.get_content_type()=="application/x-pkcs7-mime":
        sm = SMIMEUtils.SMIMEHelper(mlist)
        ciphertext = msg.as_string()
        (plaintext, signed) = sm.decryptMessage(ciphertext)
    else:
        # don't touch the message if it's no S/MIME
        return (encrypted, signed)

    parser = Parser()
    tmpmsg = parser.parsestr(plaintext)

    msg.del_param("x-action")

    for i in ('Content-Type','Content-Disposition','Content-Transfer-Encoding'):
        if tmpmsg.has_key(i):
            if msg.has_key(i):
                msg.replace_header(i,tmpmsg.get(i))
            else:
                msg.add_header(i,tmpmsg.get(i))

    tmppayload = tmpmsg.get_payload()
    msg.set_payload(tmppayload)

    if encrypted:
        msg.add_header('X-Mailman-SLS-decrypted', 'Yes')

    return (encrypted, signed)


class ModeratedMemberPost(Hold.ModeratedPost):
    # BAW: I wanted to use the reason below to differentiate between this
    # situation and normal ModeratedPost reasons.  Greg Ward and Stonewall
    # Ballard thought the language was too harsh and mentioned offense taken
    # by some list members.  I'd still like this class's reason to be
    # different than the base class's reason, but we'll use this until someone
    # can come up with something more clever but inoffensive.
    #
    # reason = _('Posts by member are currently quarantined for moderation')
    pass



def process(mlist, msg, msgdata):
    if msgdata.get('approved'):
        return
    # Deal with encrypted messages

    encrypted_gpg = False
    encrypted_smime = False
    signed = False
    key_ids = []
    signedByMember = False
    # To record with which properties we received this message.
    # This will be important later when distributing it: we want
    # to be able to support policies like "was incoming signed?
    # then distribute signed."
    msgdata['encrypted_gpg'] = False
    msgdata['encrypted_smime'] = False
    msgdata['signed_gpg'] = False
    msgdata['signed_smime'] = False

    # legal values are:
    #    0 = "No"
    #    1 = "Voluntary"
    #    2 = "Mandatory"
    if mlist.encrypt_policy!=0:
        # if msg is encrypted, we should decrypt. Try both supported types.
        (encrypted_gpg, signed, key_ids) = decryptGpg(mlist, msg, msgdata)
        (encrypted_smime, signedByMember) = decryptSmime(mlist, msg, msgdata)
        if encrypted_gpg:
            msgdata['encrypted_gpg'] = True
        if encrypted_smime:
            msgdata['encrypted_smime'] = True

        if mlist.encrypt_policy==2 and not encrypted_gpg and not encrypted_smime:
            syslog('gpg','Throwing RejectMessage exception: Message has to be GPG encrypted')
            raise Errors.RejectMessage, "Message has to be encrypted!"

    if mlist.sign_policy!=0 and not signed:
        # PGP signature matters, we have not checked while decrypting
        gh = GPGUtils.GPGHelper(mlist)
        payload = ''
        payloadmsg = None
        signatures = []
        if msg.get_content_type()=='multipart/signed' and msg.get_param('protocol')=='application/pgp-signature' and msg.is_multipart():
            # handle detached signatures, these look like:
            #
            # Content-Type: multipart/signed; micalg=pgp-sha1; protocol="application/pgp-signature"; boundary="x0ZPnva+gsdVsg/k"
            # Content-Disposition: inline
            #
            #
            # --x0ZPnva+gsdVsg/k
            # Content-Type: text/plain; charset=us-ascii
            # Content-Disposition: inline
            #
            # hello
            #
            # --x0ZPnva+gsdVsg/k
            # Content-Type: application/pgp-signature; name="signature.asc"
            # Content-Description: Digital signature
            # Content-Disposition: inline
            #
            # -----BEGIN PGP SIGNATURE-----
            # Version: GnuPG v1.2.5 (GNU/Linux)
            #
            # iD8DBQFCQDTGPSnqOAwU/4wRAsoZAKDtN6Pn1dXjC/DAQhqOLHNI6VfNigCfaDPs
            # FRJlhlGvyhkpx4soGR+CLxE=
            # =AmS5
            # -----END PGP SIGNATURE-----
            #
            # --x0ZPnva+gsdVsg/k--
            #
            # for verification, use payload INCLUDING MIME header:
            #
            # 'Content-Type: text/plain; charset=us-ascii
            #  Content-Disposition: inline
            #
            #  hello
            # '
            # Thanks Wessel Dankers for hint.

            for submsg in msg.get_payload():
                if submsg.get_content_type()=='application/pgp-signature':
                    signatures.append(submsg.get_payload())
                else:
                    if not payload:
                        # yes, including headers
                        payload = submsg.as_string()
                    else:
                        # we only deal with exactly one payload part and one or more signatures parts
                        syslog('gpg','multipart/signed message with more than one body')
                        do_discard(mlist, msg)
        elif msg.get_content_type()=='text/plain' and not msg.is_multipart():
             # handle inline signature; message looks like e.g.
             #
             # Content-Type: text/plain; charset=iso-8859-1
             # Content-Disposition: inline
             # Content-Transfer-Encoding: 8bit
             # MIME-Version: 1.0
             #
             # -----BEGIN PGP SIGNED MESSAGE-----
             # Hash: SHA1
             #
             # blah blah
             #
             # -----BEGIN PGP SIGNATURE-----
             # Version: GnuPG v1.4.0 (GNU/Linux)
             #
             # iD8DBQFCPtWXW5ql+IAeqTIRAirPAK....
             # -----END PGP SIGNATURE-----
             signatures = [None]
             payload = msg.get_payload(decode=True)
             payloadmsg = msg
        elif msg.get_content_type()=='multipart/alternative' and msg.is_multipart():
            #GPG signed plaintext with HTML version
            for submsg in msg.get_payload():
                if submsg.get_content_type()=='text/plain':
                    if not payload:
                        # text without headers
                        signatures = [None]
                        payload = submsg.get_payload(decode=True)
                        payloadmsg = submsg
                    else:
                        # we only deal with exactly one payload part
                        Utils.report_submission(msg['Message-ID'],'Confused by MIME message structure, discarding.')
                        syslog('gpg','multipart/alternative message with more than one plaintext')                        
                        do_discard(mlist, msg)
        elif msg.get_content_type()=='multipart/mixed' and msg.is_multipart():
            #GPG signed plaintext with attachments. Use first plaintext part (more text attachments are perfectly valid here)
            #TODO submsg may be multipart/alternative itself or whatever structure - is that used in the wild anywhere?
            for submsg in msg.get_payload():
                if submsg.get_content_type()=='text/plain':
                    # text without headers
                    payload = submsg.get_payload(decode=True)
                    payloadmsg = submsg
                    if payload.lstrip().startswith('-----BEGIN PGP '):
                        signatures = [None]
                        break
                elif submsg.get_content_type() in set(['application/pgp-encrypted', 'application/pgp']):
                    signatures = [None]
                    payload = submsg.get_payload(decode=True)
                    payloadmsg = submsg
                    submsg.set_type('text/plain; charset="utf-8"')
                    break
                elif submsg.get_content_type()=='multipart/alternative' and submsg.is_multipart():
                    #GPG signed plaintext with HTML version
                    for subsubmsg in submsg.get_payload():
                        if subsubmsg.get_content_type()=='text/plain':
                            if not payload:
                                # text without headers
                                payload = subsubmsg.get_payload(decode=True)
                                if payload.lstrip().startswith('-----BEGIN PGP '):
                                    signatures = [None]
                                    payloadmsg = subsubmsg
                            else:
                                # we only deal with exactly one payload part
                                syslog('gpg','multipart/alternative message with more than one plaintext')
                                Utils.report_submission(msg['Message-ID'],'Confused by MIME message structure, discarding.')
                                do_discard(mlist, msg)
                    if len(signatures) == 0:
                        payload = None
                        payloadmsg = None
                    elif payload:
                        break

        #TODO S/MIME broken atm
        #for signature in signatures:
        if signatures:
             syslog('gpg', "gonna verify payload with signature '%s'", signatures[0])
             key_ids.extend(gh.verifyMessage(payload, signatures[0],
                                             decrypted_checksum=mm_cfg.SCRUBBER_ADD_PAYLOAD_HASH_FILENAME))
        else:
            Utils.report_submission(msg['Message-ID'],'No clearsigned text part found, discarding.')


    if mlist.sign_policy!=0 and not signedByMember:
        # S/MIME signature matters, we have not checked while decrypting
        sm = SMIMEUtils.SMIMEHelper(mlist)
        payload = ''
        signature = ''

        syslog('gpg', "gonna verify SMIME message")
        signedByMember = sm.verifyMessage(msg)
        # raise Errors.NotYetImplemented, "SMIMEUtils doesn't yet do verifyMessage"

    # By now we know whether we have any valid signatures on the message.
    if signedByMember:
        msgdata['signed_smime'] = True
    if key_ids:
        msgdata['signed_gpg'] = True
        if payloadmsg and mm_cfg.SCRUBBER_ADD_PAYLOAD_HASH_FILENAME:
            sha = key_ids.pop(0)
            msgfrom = key_ids[0]
            #Kill the message if such text+signature was already posted.
            #Payload(spaces, newlines) is normalized by gpg decryption before hashing.
            if ospath.exists(ospath.join(mlist.archive_dir(),'attachments','links', msgfrom + '_' + sha)):
                Utils.report_submission(msg['Message-ID'],'Detected attempt to resubmit duplicate clearsigned text, discarding.')
                syslog('gpg','Attempt to pass clearsigned duplicate fp: %s sha1: %s' % (msgfrom, sha))
                do_discard(mlist, msg)

            payloadmsg.add_header(mm_cfg.SCRUBBER_SHA1SUM_HEADER, sha)
            payloadmsg.add_header(mm_cfg.SCRUBBER_SIGNEDBY_HEADER, msgfrom)


    if mlist.sign_policy!=0:
        if not key_ids and not signedByMember and mlist.sign_policy==2:
            Utils.report_submission(msg['Message-ID'],'Signature verification on clearsigned text failed, discarding. Review the message in your sent mail folder for wordwrap or similar mutilations of clearsigned text.')
            syslog('gpg','No valid signatures on message')
            do_discard(mlist, msg)

        if key_ids:
            gh = GPGUtils.GPGHelper(mlist)
            senderMatchesKey = False
            for key_id in key_ids:
                key_addrs = gh.getMailaddrs(key_id)
                for sender in msg.get_senders():
                    for key_addr in key_addrs:
                        if sender==key_addr:
                            senderMatchesKey = True
                            break
            if not senderMatchesKey:
                syslog('gpg','Message signed by key %s which does not match message sender %s, passing anyway' %(key_ids,msg.get_senders()))
                #temp fix
                #do_discard(mlist, msg)
        #we use gpg keyring in lieu of memberlist
        signedByMember = True
#         for user in mlist.getMembers():
#             syslog('gpg','Checking signature: listmember %s',user)
#             for key_id in key_ids:
#                 syslog('gpg','Checking signature: key_id %s',key_id)
#                 try:
#                     ks=mlist.getGPGKeyIDs(user)
#                 except:
#                     ks=None
#                 if ks:
#                     for k in mlist.getGPGKeyIDs(user):
#                         syslog('gpg','Checking signature: keyid of listmember is %s',k)
#                         if k==key_id:
#                             signedByMember = True
#                             break

    # done dealing with most of gpg stuff

    # Is the poster a member or not?
    for sender in msg.get_senders():
        if mlist.isMember(sender):
            break
        for sender in Utils.check_eq_domains(sender,
                          mlist.equivalent_domains):
            if mlist.isMember(sender):
                break
        if mlist.isMember(sender):
            break
    else:
        sender = None
    if sender:
        # If posts need to be PGP signed, process signature.
        if mlist.sign_policy==2:
            if signedByMember==True:
                syslog('gpg','Message properly signed: distribute')
                return
            else:
                do_discard(mlist, msg)

        # If the member's moderation flag is on, then perform the moderation
        # action.
        if mlist.getMemberOption(sender, mm_cfg.Moderate):
            # Note that for member_moderation_action, 0==Hold, 1=Reject,
            # 2==Discard
            if mlist.member_moderation_action == 0:
                # Hold.  BAW: WIBNI we could add the member_moderation_notice
                # to the notice sent back to the sender?
                msgdata['sender'] = sender
                Hold.hold_for_approval(mlist, msg, msgdata,
                                       ModeratedMemberPost)
            elif mlist.member_moderation_action == 1:
                # Reject
                text = mlist.member_moderation_notice
                if text:
                    text = Utils.wrap(text)
                else:
                    # Use the default RejectMessage notice string
                    text = None
                raise Errors.RejectMessage, text
            elif mlist.member_moderation_action == 2:
                # Discard.  BAW: Again, it would be nice if we could send a
                # discard notice to the sender
                raise Errors.DiscardMessage
            else:
                assert 0, 'bad member_moderation_action'
        # Should we do anything explict to mark this message as getting past
        # this point?  No, because further pipeline handlers will need to do
        # their own thing.
        return
    else:
        sender = msg.get_sender()
    # From here on out, we're dealing with non-members.
    listname = mlist.internal_name()
    if matches_p(sender, mlist.accept_these_nonmembers, listname):
        return
    if matches_p(sender, mlist.hold_these_nonmembers, listname):
        Hold.hold_for_approval(mlist, msg, msgdata, Hold.NonMemberPost)
        # No return
    if matches_p(sender, mlist.reject_these_nonmembers, listname):
        do_reject(mlist)
        # No return
    if matches_p(sender, mlist.discard_these_nonmembers, listname):
        do_discard(mlist, msg)
        # No return
    # Okay, so the sender wasn't specified explicitly by any of the non-member
    # moderation configuration variables.  Handle by way of generic non-member
    # action.
    assert 0 <= mlist.generic_nonmember_action <= 4
    if mlist.generic_nonmember_action == 0 or msgdata.get('fromusenet'):
        # Accept
        return
    elif mlist.generic_nonmember_action == 1:
        Hold.hold_for_approval(mlist, msg, msgdata, Hold.NonMemberPost)
    elif mlist.generic_nonmember_action == 2:
        do_reject(mlist)
    elif mlist.generic_nonmember_action == 3:
        do_discard(mlist, msg)



def matches_p(sender, nonmembers, listname):
    # First strip out all the regular expressions and listnames
    plainaddrs = [addr for addr in nonmembers if not (addr.startswith('^')
                                                 or addr.startswith('@'))]
    addrdict = Utils.List2Dict(plainaddrs, foldcase=1)
    if addrdict.has_key(sender):
        return 1
    # Now do the regular expression matches
    for are in nonmembers:
        if are.startswith('^'):
            try:
                cre = re.compile(are, re.IGNORECASE)
            except re.error:
                continue
            if cre.search(sender):
                return 1
        elif are.startswith('@'):
            # XXX Needs to be reviewed for list@domain names.
            try:
                mname = are[1:].lower().strip()
                if mname == listname:
                    # don't reference your own list
                    syslog('error',
                        '*_these_nonmembers in %s references own list',
                        listname)
                else:
                    mother = MailList(mname, lock=0)
                    if mother.isMember(sender):
                        return 1
            except Errors.MMUnknownListError:
                syslog('error',
                  '*_these_nonmembers in %s references non-existent list %s',
                  listname, mname)
    return 0



def do_reject(mlist):
    listowner = mlist.GetOwnerEmail()
    if mlist.nonmember_rejection_notice:
        raise Errors.RejectMessage, \
              Utils.wrap(_(mlist.nonmember_rejection_notice))
    else:
        raise Errors.RejectMessage, Utils.wrap(_("""\
Your message has been rejected, probably because you are not subscribed to the
mailing list and the list's policy is to prohibit non-members from posting to
it.  If you think that your messages are being rejected in error, contact the
mailing list owner at %(listowner)s."""))



def do_discard(mlist, msg):
    sender = msg.get_sender()
    # Do we forward auto-discards to the list owners?
    if mlist.forward_auto_discards:
        lang = mlist.preferred_language
        varhelp = '%s/?VARHELP=privacy/sender/discard_these_nonmembers' % \
                  mlist.GetScriptURL('admin', absolute=1)
        nmsg = Message.UserNotification(mlist.GetOwnerEmail(),
                                        mlist.GetBouncesEmail(),
                                        _('Auto-discard notification'),
                                        lang=lang)
        nmsg.set_type('multipart/mixed')
        text = MIMEText(Utils.wrap(_(
            'The attached message has been automatically discarded.')),
                        _charset=Utils.GetCharSet(lang))
        nmsg.attach(text)

        decrypted = msg.get('X-Mailman-SLS-decrypted', '').lower()
        if decrypted == 'yes':
            syslog('gpg',
 'forwarding only headers of message from %s to listmaster to notify discard since message was decrypted',
 sender)
            msgtext = msg.as_string()
            (header, body) = msgtext.split("\n\n", 1)
            nmsg.attach(MIMEText(header))
        else:
            nmsg.attach(MIMEMessage(msg))

        nmsg.send(mlist)
    # Discard this sucker
    raise Errors.DiscardMessage
