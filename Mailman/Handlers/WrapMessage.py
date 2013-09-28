# Copyright (C) 2013 by the Free Software Foundation, Inc.
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
    if not mm_cfg.ALLOW_FROM_IS_LIST or mlist.from_is_list != 2:
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
    # And set the payload.
    msg.set_payload(omsg.as_string())

