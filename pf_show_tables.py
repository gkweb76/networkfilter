#!/usr/local/bin/python3.5
# File: pf_show_tables.py
# Version: 1.0
# Date: 2017/04/21
# Blog: https://networkfilter.blogspot.com
import subprocess
import re
from collections import defaultdict, OrderedDict


pf_file         = '/etc/pf.conf'
rule_tag_new    = 'new_guy'
rule_tag_old    = 'old_guy'
rule_id         = 0
pf_ruleset      = 'pfctl -sr'
pf_badguys      = 'pfctl -t badguys -T show'
pf_bruteforce   = 'pfctl -t bruteforce -T show'
pf_stats        = 'pfctl -sl'

get_blocked_ips = 'tcpdump -enr /var/log/pflog'
counter         = 0

def execute(cmd):
    "Execute the provided commmand and return its output "
    output = subprocess.getoutput(cmd)
    return output.split('\n')

def getKey(item):
    "Return the item to base the sort on, used by sorted() function"
    return item[1]


# Retrieve all blocked IPs from /var/log/pflog
blocked_ips = execute(get_blocked_ips)

# Parse blocked IPs and ports and sort them out
blocked_list = defaultdict(list)
stats_ip     = defaultdict(list)
stats_ports  = defaultdict(list)
ip           = ''

total_block = 0
for logline in range(len(blocked_ips)):
    if ('/(match) block in on') in blocked_ips[logline]: # if an inbound block was logged
        ip = blocked_ips[logline].split()[7]             # retrieve ip.port
        total_block += 1

        if not 'icmp' in blocked_ips[logline]:
            port = ip.split('.')[4]
        else:
            port = 'icmp'

        ip = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.' + ip.split('.')[3]

        # Keep track of IP:ports tried, e.g: 127.0.0.1 : 21, 80, 443, 443, 443, 8080, ...
        blocked_list[ip].append(port)

        # Keep track of how many deny per IP, e.g: 127.0.0.1 : 5, 127.0.0.2 : 1, ...
        if stats_ip.get(ip, 'NA') == 'NA':
            stats_ip[ip] = 1
        else:
            stats_ip[ip] = stats_ip[ip] + 1

        # Keep track of how many deny per port, e.g: 80 : 5, 443 : 20, ...
        if stats_ports.get(port, 'NA') == 'NA':
            stats_ports[port] = 1
        else:
            stats_ports[port] = stats_ports[port] + 1

# Final ordered lists, about top blocked IPs and ports
top_ports = OrderedDict(sorted(stats_ports.items(), key=getKey, reverse=True))
top_ips   = OrderedDict(sorted(stats_ip.items(), key=getKey, reverse=True))

print('\nStatistics:')
print('-------------')
print('Blacklisted IPs: %d' % len(execute(pf_badguys)))
print('Blocks : %d' % total_block)

print('\nTOP blocked IPs:')
print('------------------')
count = 0
max   = 5
for ip in top_ips:
    if top_ips[ip] > 1:
        print('%s : %d times ' % (ip, top_ips[ip]))127.0.0.1 : 5, 127.0.0.2 : 1, ...
        count +=1
        if count == max: break

print('\nTOP blocked ports:')
print('--------------------')
count = 0
for port in top_ports:
    if top_ports[port] > 1:
            print('%s : %d times ' % (port, top_ports[port]))
            count +=1
            if count == max: break
