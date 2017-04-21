#!/usr/local/bin/python3.5
# File: block_intruders.py
# Version: 1.0
# Date: 2017/04/21
# Blog: https://networkfilter.blogspot.com
import subprocess

# Modify below your home path, and your trusted public IP address you connect from
badguys_file    = '/home/guillaume/badguys.txt'
pf_file         = '/etc/pf.conf'
rule_tag        = 'new_guy'
rule_id         = 0
get_ruleset     = 'pfctl -sr'
get_blocked_ips = 'tcpdump -enr /var/log/pflog'
block_badguys   = 'pfctl -t badguys -T add -f ' + badguys_file
counter         = 0
trusted         = ['YOUR_PUBLIC_IP_HERE']

def execute(cmd):
    "Execute the provided commmand and return its output "
    output = subprocess.getoutput(cmd)
    return output.split('\n')

# Retrieve loaded rules with 'pfctl -sr'
ruleset = execute(get_ruleset)

# Locate our blacklisting rule ID
for rule in ruleset:
    counter += 1
    if rule_tag in rule:
        rule_id = counter - 1
        break

# Retrieve all blocked IPs from /var/log/pflog
blocked_ips = execute(get_blocked_ips)

# Match only IPs blocked by our blacklisting rule
badguys = []
for logline in range(len(blocked_ips)):
    if ('rule ' + str(rule_id) + '/(match) block') in blocked_ips[logline]:
        ip = blocked_ips[logline].split()[7] # retrieve ip.port
        ip = ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.' + ip.split('.')[3]
        badguys.append(ip)

# Remove duplicate IPs
badguys = list(set(badguys))

# Remove your trusted IPs from the list!
for good_ip in trusted:
    for bad_ip in badguys:
        if bad_ip == good_ip:
            badguys.remove(bad_ip)
            
# Writing the list of bad IPs to a file
with open(badguys_file, 'w') as file:
    for ip in badguys:
        file.write(ip + '\n')

# Finally blocking the badguys ;-(
execute(block_badguys)
