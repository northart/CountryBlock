#!/bin/bash

# Shawn Northart <northart@gmail.com>

# use ipset w/iptables to block countries
# should be safe to run from cron once a day.

IPT=/sbin/iptables
SET=/sbin/ipset
WGET=/usr/bin/wget

# Two-letter country codes for countries we want to block.
CC=( ae ar bd cn hk id in iq ir kh kr nl pe ph pk ro ru rs sa sg sy tr tw ua uy vn za )


# let's run blocklist.de first
if [[ ! $(${IPT} -nL | grep "match-set blocklist_de") ]] ; then
  $SET -N blocklist_de iphash
  for IP in $(${WGET} -q -O - https://lists.blocklist.de/lists/all.txt | egrep -v ':')
  do
    $SET -A blocklist_de $IP

  done
  $IPT -I INPUT -m set --match-set blocklist_de src -j DROP

else
  $SET flush blocklist_de
  for IP in $(${WGET} -q -O - https://lists.blocklist.de/lists/all.txt | egrep -v ':')
  do
    $SET add blocklist_de $IP

  done
fi

# block tor exit nodes
if [[ ! $(${IPT} -nL | grep "match-set tor_exit_nodes") ]] ; then
  $SET -N tor_exit_nodes iphash
  for IP in $(${WGET} -q "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=45.79.95.251&port=22" -O -|sed '/^#/d')
  do
    $SET -A tor_exit_nodes $IP

  done
  $IPT -I INPUT -m set --match-set tor_exit_nodes src -j DROP

else
  $SET flush tor_exit_nodes
  for IP in $(${WGET} -q "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=45.79.95.251&port=22" -O -|sed '/^#/d')
  do
    $SET add tor_exit_nodes $IP

  done
fi

# now let's loop through our country blocks
for COUNTRY in "${CC[@]}"
do
  sleep 1
  if [[ ! $(${IPT} -nL | grep "match-set ${COUNTRY}_block") ]] ; then
    $SET -N "$COUNTRY"_block nethash
    for IP in $(${WGET} -q -O - http://www.ipdeny.com/ipblocks/data/countries/${COUNTRY}.zone)
    do
      $SET -A "$COUNTRY"_block $IP

    done
    $IPT -I INPUT -m set --match-set "$COUNTRY"_block src -j DROP

  else
    $SET flush "$COUNTRY"_block
    for IP in $(${WGET} -q -O - http://www.ipdeny.com/ipblocks/data/countries/${COUNTRY}.zone)
    do
      $SET add "$COUNTRY"_block $IP

    done
  fi
done

# That's all folks!
