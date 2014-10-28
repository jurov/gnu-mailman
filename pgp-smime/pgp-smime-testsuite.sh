#!/bin/sh

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


# Create 3 lists.  The test vanilla (named test-gpg-vanilla) list has settings:
# 
#  gpg_post_encrypt    No
#  gpg_distrib_encrypt No
#  gpg_post_sign       No
#  gpg_distrib_sign    No
# 
# smime_-settings are the same.
# 
# The test-gpg-medium list has settings:
# 
#  gpg_post_encrypt    Yes
#  gpg_distrib_encrypt Yes
#  gpg_post_sign       Force
#  gpg_distrib_sign    No
# 
# A similar list test-smime-medium should be created.
# 
# The test-gpg-secure list has settings:
# 
#  gpg_post_encrypt    Yes           (encrypt post to listkey)
#  gpg_distrib_encrypt Force         (distribute encypted)
#  gpg_post_sign       Force         (should posts be signed)
#  gpg_distrib_sign    Yes           (distribute signed)
#
# A similar list test-smime-secure should be created.
#

# 
# Conduct tests by posting various messages to various lists and make sure all
# tests are passed.  Send as
# 
#  subscriber with uploaded key
#  subscriber without uploaded key
#  non-subscriber
# 
# .
# 
# plain to test-vanilla:     (plain)
# signed to test-vanilla:    (signed)
# encrypted to test-vanilla: (encrypted to same (unkown) key)
# 
# For both pgp and s/mime:
# 
# plain to test-medium:      (discard)
# signed to test-medium:     (crypt)
# encrypted to test-medium:  (crypt)
# signed+encrypted to test-medium:
# 
# For both pgp and s/mime:
# 
# plain to test-secure:      (discard)
# signed to test-secure:     (discard)
# encrypted to test-secure:  (crypt)
# signed+encrypted to test-secure:




# TODO FIXME
# some test messages are in
# joostvb@bruhat:~/var/lib% mkdir -p mailman-pgp-smime/testmails

# Example usage:
#
#  pgp-smime-testsuite.sh joostvb-mailman-pgp-smime-test@bruhat.mdcc.cx SeCrEt joostvb-testlist-member@bruhat.mdcc.cx
#

set -ex

listadmin_addr="$1"
admin_password="$2"
member_addr="$3" # just one testmember, the same for all lists joostvb-testlist-member@bruhat.mdcc.cx

tmpdir=`mktemp -d`
trap 'rm -rf $tmpdir' EXIT

for s in vanilla medium secure
do
    for e in gpg smime
    do
        l=test-$e-$s

        if list_lists --bare | grep "^$l"
        then
            echo list $l already exists, skipping creation
        else
            # list@bruhat:/% /opt/mailman/bin/newlist
            newlist --quiet $l $listadmin_addr $admin_password

            mktemp -d

            touch $tmpdir/$l.isnew
        fi
    done
done


{ cat <<EOT
vanilla post_encrypt    0
vanilla distrib_encrypt 0
vanilla post_sign       0
vanilla distrib_sign    0
medium post_encrypt     1
medium distrib_encrypt  1
medium post_sign        2
medium distrib_sign     0
secure post_encrypt     1
secure distrib_encrypt  2
secure post_sign        2
secure distrib_sign     1
EOT
} | while read s o v; do
  for e in gpg smime
  do
        l=test-$e-$s

        if test -f $tmpdir/$l.isnew
        then
            # we've just created this list, configure it

            # use changeoption.py
            # withlist -l -r changeoption.changeoption $l $o $v
            # withlist -l -r changeoption $l $o $v

            conffile=$tmpdir/$l.conf

            config_list -o - $l >$conffile

            option=${e}_${o}
            grep -v ${option} $conffile >$conffile,new
            echo "${option} = $v" >>$conffile,new

            config_list -i $conffile,new $l

        fi
    done
    # test-vanilla test-gpg-medium
done

# subscribe test user to lists
for s in vanilla medium secure
do
    for e in gpg smime
    do
        l=test-$e-$s
        echo $member_addr | add_members -r - $l
        # this behaves sane if already a member
    done
done

# test emails should be in the current directory
for m in *.msg
do
     # -f sender   Set the envelope sender  address.
     sendmail -oi -t < $m
done

