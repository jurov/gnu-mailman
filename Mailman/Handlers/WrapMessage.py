# Copyright (C) 2013-2014 by the Free Software Foundation, Inc.
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

"""Wrap the message in an outer message/rfc822 part and transfer/add
some headers from the original.

Also, in the case of Munge From, replace the From: and Reply-To: in the
original message.
"""

import copy

from Mailman import mm_cfg
from Mailman.Utils import unique_message_id
from Mailman.Message import Message

# Headers from the original that we want to keep in the wrapper.
KEEPERS = ('to',
           'in-reply-to',
           'references',
           'x-mailman-approved-at',
          )



def process(mlist, msg, msgdata):
    # This is the negation of we're wrapping because dmarc_moderation_action
    # is wrap this message or from_is_list applies and is wrap.
    if not (msgdata.get('from_is_list') == 2 or
            (mlist.from_is_list == 2 and msgdata.get('from_is_list') == 0)):
        # Now see if we need to add a From: and/or Reply-To: without wrapping.
        a_h = msgdata.get('add_header')
        if a_h:
            if a_h.get('From'):
                del msg['from']
                msg['From'] = a_h.get('From')
            if a_h.get('Reply-To'):
                del msg['reply-to']
                msg['Reply-To'] = a_h.get('Reply-To')
        return

    # There are various headers in msg that we don't want, so we basically
    # make a copy of the msg, then delete almost everything and set/copy
    # what we want.
    omsg = copy.deepcopy(msg)
    for key in msg.keys():
        if key.lower() not in KEEPERS:
            del msg[key]
    msg['MIME-Version'] = '1.0'
    msg['Content-Type'] = 'message/rfc822'
    msg['Content-Disposition'] = 'inline'
    msg['Message-ID'] = unique_message_id(mlist)
    # Add the headers from CookHeaders.
    for k, v in msgdata['add_header'].items():
        msg[k] = v
    # And set the payload the way email parses it.
    msg.set_payload([omsg])

