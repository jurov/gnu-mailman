# Copyright (C) 1998-2012 by the Free Software Foundation, Inc.
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

"""Do more detailed spam detection.

This module hard codes site wide spam detection.  By hacking the
KNOWN_SPAMMERS variable, you can set up more regular expression matches
against message headers.  If spam is detected the message is discarded
immediately.

TBD: This needs to be made more configurable and robust.
"""

import re

from email.Header import decode_header

from Mailman import mm_cfg
from Mailman import Errors
from Mailman import i18n
from Mailman.Utils import GetCharSet
from Mailman.Handlers.Hold import hold_for_approval

try:
    True, False
except NameError:
    True = 1
    False = 0

# First, play footsie with _ so that the following are marked as translated,
# but aren't actually translated until we need the text later on.
def _(s):
    return s



class SpamDetected(Errors.DiscardMessage):
    """The message contains known spam"""

class HeaderMatchHold(Errors.HoldMessage):
    reason = _('The message headers matched a filter rule')


# And reset the translator
_ = i18n._



def getDecodedHeaders(msg, cset='utf-8'):
    """Returns a string containing all the headers of msg, unfolded and
    RFC 2047 decoded and encoded in cset.
    """

    headers = ''
    for h, v in msg.items():
        uvalue = u''
        v = decode_header(re.sub('\n\s', ' ', v))
        for frag, cs in v:
            if not cs:
                cs = 'us-ascii'
            uvalue += unicode(frag, cs, 'replace')
        headers += '%s: %s\n' % (h, uvalue.encode(cset, 'replace'))
    return headers



def process(mlist, msg, msgdata):
    if msgdata.get('approved'):
        return
    # First do site hard coded header spam checks
    for header, regex in mm_cfg.KNOWN_SPAMMERS:
        cre = re.compile(regex, re.IGNORECASE)
        for value in msg.get_all(header, []):
            mo = cre.search(value)
            if mo:
                # we've detected spam, so throw the message away
                raise SpamDetected
    # Now do header_filter_rules
    # TK: Collect headers in sub-parts because attachment filename
    # extension may be a clue to possible virus/spam.
    headers = ''
    # Get the character set of the lists preferred language for headers
    lcset = GetCharSet(mlist.preferred_language)
    for p in msg.walk():
        headers += getDecodedHeaders(p, lcset)
    for patterns, action, empty in mlist.header_filter_rules:
        if action == mm_cfg.DEFER:
            continue
        for pattern in patterns.splitlines():
            if pattern.startswith('#'):
                continue
            # ignore 'empty' patterns
            if not pattern.strip():
                continue
            if re.search(pattern, headers, re.IGNORECASE|re.MULTILINE):
                if action == mm_cfg.DISCARD:
                    raise Errors.DiscardMessage
                if action == mm_cfg.REJECT:
                    if msgdata.get('toowner'):
                        # Don't send rejection notice if addressed to '-owner'
                        # because it may trigger a loop of notices if the
                        # sender address is forged.  We just discard it here.
                        raise Errors.DiscardMessage
                    raise Errors.RejectMessage(
                        _('Message rejected by filter rule match'))
                if action == mm_cfg.HOLD:
                    if msgdata.get('toowner'):
                        # Don't hold '-owner' addressed message.  We just
                        # pass it here but list-owner can set this to be
                        # discarded on the GUI if he wants.
                        return
                    hold_for_approval(mlist, msg, msgdata, HeaderMatchHold)
                if action == mm_cfg.ACCEPT:
                    return
