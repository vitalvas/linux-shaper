#!/usr/bin/env python
# usage: python shaper.py | bash

from os import system

class Shaper:
    def __init__(self):
	self.if_up = 'eth0'
	self.if_down = 'eth1'
	self.modprobe = '/sbin/modprobe'
	self.modprobe_modules = [ 'ipt_set', 'ip6_tables', 'ip6t_set' ]
	self.sysctl = '/sbin/sysctl -qw'
	self.sysctl_kernel = { 'net.ipv4.ip_forward':1, 'net.ipv6.conf.all.forwarding':1 }
	self.iptables = '/sbin/iptables'
	self.ip6tables = '/sbin/ip6tables'
	self.ipset = '/usr/sbin/ipset'
	self.tc = '/sbin/tc'
	self.cmds = []

    def init(self):
	map(lambda x: self.cmds.append( ' '.join([ self.modprobe, x ]) ), self.modprobe_modules )
	map(lambda x: self.cmds.append( ' '.join([ self.sysctl, '='.join([ x, str(self.sysctl_kernel[x]) ]) ]) ), self.sysctl_kernel)
	self.ipv4()
	self.ipv6()
	self.shaper()
	print '\n'.join(self.cmds)

    def ipv4(self):
	cmds = []
	for tble in [ 'filter', 'nat', 'mangle' ]:
	    cmds.append(' '.join([ self.iptables, '-t', tble, '-F']))
	    cmds.append(' '.join([ self.iptables, '-t', tble, '-X']))

	for ips in [ 'accept', 'smtp', 'dns' ]:
	    cmds.append(' '.join([ self.ipset, 'destroy', ips]))
	    cmds.append(' '.join([ self.ipset, 'create', ips, 'nethash hashsize 64']))

	ipt = [
	    '-t filter -P INPUT DROP',
	    '-t filter -P FORWARD DROP',
	    '-t filter -P OUTPUT ACCEPT',
	    '-t filter -A INPUT -i lo -j ACCEPT',
	    '-t filter -A INPUT -p icmp --icmp-type echo-request -j ACCEPT',
	    '-t filter -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT',
	    '-t filter -A INPUT -i %(if_down)s -p tcp --dport 7332 -m conntrack --ctstate NEW -j ACCEPT',
	    '-t filter -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
	    '-t filter -A INPUT -i %(if_down)s -p udp --dport 67 -j ACCEPT',
	    '-t filter -A INPUT -i %(if_down)s -m pkttype --pkt-type broadcast -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_down)s -o %(if_up)s -p tcp --dport 25 -m set ! --match-set smtp src -j DROP',
	    '-t filter -A FORWARD -i %(if_up)s -o %(if_down)s -m set --match-set accept dst -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_down)s -o %(if_up)s -m set --match-set accept src -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_up)s -o %(if_down)s -p udp --sport 53 -m set --match-set dns src -m set ! --match-set accept dst -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_down)s -o %(if_up)s -p udp --dport 53 -m set --match-set dns dst -m set ! --match-set accept src -j ACCEPT',
	    '-t nat -A PREROUTING -i %(if_down)s -p tcp -m tcp --dport 80 -m set ! --match-set accept src -j REDIRECT --to-ports 7332',
	    '-t nat -A POSTROUTING -s 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j MASQUERADE',
	    '-t mangle -N shaper_s',
	    '-t mangle -N shaper_d',
	    '-t mangle -A FORWARD -i %(if_down)s -o %(if_up)s -m set --match-set accept src -j shaper_s',
	    '-t mangle -A FORWARD -i %(if_up)s -o %(if_down)s -m set --match-set accept dst -j shaper_d',
	]

	cmds += map(lambda x: ' '.join([ self.iptables, x]), map(lambda x: x % self.__dict__, ipt))
	self.cmds += cmds

    def ipv6(self):
	cmds = []
	for tble in [ 'filter', 'mangle' ]:
	    cmds.append(' '.join([ self.ip6tables, '-t', tble, '-F']) )
	    cmds.append(' '.join([ self.ip6tables, '-t', tble, '-X']))

	for ips in ['accept6', 'smtp6', 'dns6']:
	    cmds.append(' '.join([ self.ipset, 'destroy', ips]))
	    cmds.append(' '.join([ self.ipset, 'create', ips, 'nethash family inet6 hashsize 64']))

	ipt = [
	    '-t filter -P FORWARD DROP',
	    '-t filter -A FORWARD -i %(if_down)s -o %(if_up)s -p tcp --dport 25 -m set ! --match-set smtp6 src -j DROP',
	    '-t filter -A FORWARD -i %(if_up)s -o %(if_down)s -m set --match-set accept6 dst -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_down)s -o %(if_up)s -m set --match-set accept6 src -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_up)s -o %(if_down)s -p udp --sport 53 -m set --match-set dns6 src -m set ! --match-set accept6 dst -j ACCEPT',
	    '-t filter -A FORWARD -i %(if_down)s -o %(if_up)s -p udp --dport 53 -m set --match-set dns6 dst -m set ! --match-set accept6 src -j ACCEPT',
	    '-t mangle -N shaper_s',
	    '-t mangle -N shaper_d',
	    '-t mangle -A FORWARD -i %(if_down)s -o %(if_up)s -m set --match-set accept6 src -j shaper_s',
	    '-t mangle -A FORWARD -i %(if_up)s -o %(if_down)s -m set --match-set accept6 dst -j shaper_d',
	]

	cmds += map(lambda x: ' '.join([ self.ip6tables, x]), map(lambda x: x % self.__dict__, ipt))
	self.cmds += cmds

    def shaper(self):
	cmds = []
	map(lambda ip: cmds.append(' '.join([ self.ipset, 'add dns', ip ])), [ '8.8.8.8', '8.8.4.4', '77.88.8.8', '77.88.8.88', '77.88.8.7' ])
	map(lambda ip: cmds.append(' '.join([ self.ipset, 'add dns6', ip])), [ '2001:4860:4860::8888', '2001:4860:4860::8844', '2a01:d0::1' ])
	tc = [
	    'qdisc del dev %(if_up)s root',
	    'qdisc del dev %(if_down)s root',
	    'qdisc add dev %(if_up)s root handle 1: htb default 0 r2q 3000',
	    'qdisc add dev %(if_down)s root handle 2: htb default 0 r2q 3000'
	]

	i, ipt = 1, []
	for user in [line.strip() for line in open('users.txt') if line.strip()[0] != '#']:
	    user = user.split('|')
	    tc += [
		'class add dev %s parent 1: classid 1:%s htb rate %sKbit' % (self.if_up, i, user[2]),
		'class add dev %s parent 2: classid 2:%s htb rate %sKbit' % (self.if_down, i, user[1])
	    ]
	    if ',' in user[0]:
		ipaddr = user[0].split(',')
		for ip in ipaddr:
		    iptables = self.ip6tables if ':' in ip else self.iptables
		    ipt.append(' '.join([iptables, '-t mangle -A shaper_s -i %(if_down)s -o %(if_up)s -s', ip, '-j CLASSIFY --set-class 1:%s' % i]))
		    ipt.append(' '.join([iptables, '-t mangle -A shaper_d -i %(if_up)s -o %(if_down)s -d', ip, '-j CLASSIFY --set-class 2:%s' % i]))
		    ipt.append(' '.join([self.ipset, 'add', 'accept6' if ':' in ip else 'accept', ip]))
	    else:
		iptables = self.ip6tables if ':' in user[0] else self.iptables
		ipt.append(' '.join([iptables, '-t mangle -A shaper_s -i %(if_down)s -o %(if_up)s -s', user[0], '-j CLASSIFY --set-class 1:%s' % i]))
		ipt.append(' '.join([iptables, '-t mangle -A shaper_d -i %(if_up)s -o %(if_down)s -d', user[0], '-j CLASSIFY --set-class 2:%s' % i]))
		ipt.append(' '.join([self.ipset, 'add', 'accept6' if ':' in user[0] else 'accept', user[0]]))
	    i += 1

	cmds += map(lambda x: ' '.join([ self.tc, x]), map(lambda x: x % self.__dict__, tc))
	cmds += map(lambda x: x % self.__dict__, ipt)
	self.cmds += cmds



if __name__ == '__main__':
    Shaper().init()


