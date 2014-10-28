# Copyright (C) 2008 Joost van Baal joostvb-mailman-pgp-smime/a/mdcc.cx
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

# WARNING
# This code was written to get used in pgp-smime-testsuite.sh, but
# never made it.

# list@bruhat:/% /opt/mailman/bin/withlist testlist
# >>> mlist=m
# >>> categories = mlist.GetConfigCategories()
# >>> privacy=categories['privacy']
# >>> print privacy

import paths
from Mailman import mm_cfg
from Mailman import MailList

# stolen from bin/configlist
def getPropertyMap(mlist):
    guibyprop = {}
    categories = mlist.GetConfigCategories()
    for category, (label, gui) in categories.items():
        if not hasattr(gui, 'GetConfigInfo'):
            continue
        subcats = mlist.GetConfigSubCategories(category)
        if subcats is None:
            subcats = [(None, None)]
        for subcat, sclabel in subcats:
            for element in gui.GetConfigInfo(mlist, category, subcat):
                if not isinstance(element, TupleType):
                    continue
                propname = element[0]
                wtype = element[1]
                guibyprop[propname] = (gui, wtype)
    return guibyprop

class FakeDoc:
    # Fake the error reporting API for the htmlformat.Document class
    def addError(self, s, tag=None, *args):
        if tag:
            print >> sys.stderr, tag
        print >> sys.stderr, s % args

    def set_language(self, val):
        pass

# value is 0, 1, 2
def changeoption(mlist, option, value):
    fakedoc = FakeDoc()

    guibyprop = getPropertyMap(mlist)

    missing = []
    gui, wtype = guibyprop.get(k, (missing, missing))

    gui._setValue(mlist, option, value, fakedoc)

    mlist.Save()
    mlist.Unlock()

