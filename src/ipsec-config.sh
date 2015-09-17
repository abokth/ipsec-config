#!/bin/bash

## Copyright 2015 Alexander Boström, Kungliga Tekniska högskolan
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

# This script will set up IPsec between a set of hosts, secured via
# assymetric crypto. It should be safe to run it again against a
# superset of these hosts if one host needs to be added. The arguments
# should be the canonical FQDN of each host.

set -e; set -o pipefail

type >/dev/null mktemp host ssh

declare -a hosts

while (( $# > 0 )); do
    host="$1"; shift
    hosts+=("$host")
done

echo Hosts: "${hosts[@]}"

declare -A ipv6addr ipv4addr

leftkeys=$(mktemp -d)
rightkeys=$(mktemp -d)

for h in "${hosts[@]}"; do
    ipv6=$(host -t AAAA $h | sed -nre 's,^.* has .*address (.*)$,\1,p;' | sort -u | tail -1)
    ipv4=$(host -t A    $h | sed -nre 's,^.* has .*address (.*)$,\1,p;' | sort -u | tail -1)

    ipv6addr[$h]="$ipv6"
    ipv4addr[$h]="$ipv4"

    echo "Ensuring software and key pairs exists in $h..."

    # To undo this: yum -y remove libreswan; rm -rf /etc/ipsec.d
    ssh root@"$h" 'test -e /etc/ipsec.d || yum -y install libreswan'

    ssh root@"$h" 'test -e /etc/ipsec.d/$(hostname --short).secrets || ipsec newhostkey --configdir /etc/ipsec.d --output /etc/ipsec.d/$(hostname --short).secrets'

    ssh root@"$h" ipsec showhostkey --left >"$leftkeys/$h"
    ssh root@"$h" ipsec showhostkey --right >"$rightkeys/$h"
done

declare -A pairs

ipsecconf=$(mktemp)

for left in "${hosts[@]}"; do
    short_left="${left%%.*}"

    leftv6="${ipv6addr[$left]}"
    leftv4="${ipv4addr[$left]}"

    for right in "${hosts[@]}"; do
	if [[ "$left" == "$right" ]]; then
	    # Not a pair.
	    continue
	fi

	# Ensure consistent pair orientation.
	check=$(echo -e "$left\n$right" | env LC_ALL=C sort | tail -1)
	if [[ "$right" != "$check" ]]; then
	    # Do it the other way around.
	    continue
	fi

	short_right="${right%%.*}"

	pair="${short_left}_and_${short_right}"
	invert_pair="${short_right}_and_${short_left}"

	if [[ -n "${pairs[$invert_pair]}" ]]; then
	    # Already done.
	    continue
	fi

	pairs[$pair]="$left $right"
	echo "Configuring configuration for pair: $short_left $short_right"

	rightv6="${ipv6addr[$right]}"
	rightv4="${ipv4addr[$right]}"

	cat >"$ipsecconf" <<EOF
conn secure_v6_${short_left}_and_${short_right}
	type=transport
	authby=rsasig
	auto=start

	leftid=@${short_left}
	left=$leftv6
$(cat $leftkeys/$left)

	rightid=@${short_right}
	right=$rightv6
$(cat $rightkeys/$right)

conn secure_v4_${short_left}_and_${short_right}
	type=transport
	authby=rsasig
	auto=start

	leftid=@${short_left}
	left=$leftv4
$(cat $leftkeys/$left)

	rightid=@${short_right}
	right=$rightv4
$(cat $rightkeys/$right)

EOF

	for h in "$left" "$right"; do
	    ssh root@"$h" "cat >/etc/ipsec.d/secure_$pair.conf" <"$ipsecconf"
	    ssh root@"$h" systemctl restart ipsec
	    ssh root@"$h" systemctl enable ipsec
	done
    done
done

