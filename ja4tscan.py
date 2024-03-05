import sys
import os
import ipaddress
import argparse

def setup_iptables():
    print('adding iptable rules...')
    os.system('iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')
    os.system('iptables -t filter -A INPUT -p icmp -j ACCEPT')
    os.system('iptables -t filter -A INPUT -i lo -j ACCEPT')
    os.system('iptables -t filter -A INPUT -j DROP')

def cleanup_iptables():
    print('cleaning up iptable rules...')
    os.system('iptables -t filter -D INPUT -j DROP')
    os.system('iptables -t filter -D INPUT -i lo -j ACCEPT')
    os.system('iptables -t filter -D INPUT -p icmp -j ACCEPT')
    os.system('iptables -t filter -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT')

def post_process_output(filename):
    lastlines = {}
    with open(filename) as fp:
        lines = fp.readlines()

        _idx = [ x == 'saddr' for x in lines[0].split(',') ].index(True)
        ja4_idx = [ x.rstrip() == 'ja4ts' for x in lines[0].split(',') ].index(True)

        for line in lines[1:]:
            tokens = line.split(',')
            source = int(ipaddress.ip_address(tokens[_idx]))
            if tokens[ja4_idx].lstrip().startswith('0_00_'):
                tokens[ja4_idx] = tokens[ja4_idx].replace('0_00_', 'RST-ACK_')
            if tokens[ja4_idx].rstrip().endswith('_00_00_'):
                tokens[ja4_idx] = tokens[ja4_idx].replace('_00_00_', 'rst-ack')
            lastlines[source] = ','.join(tokens) #line

    sorted_ips = sorted([ ip for ip in lastlines ])
    with open(filename, 'w') as fp:
        fp.write(lines[0])
        for ip in sorted_ips:
            fp.write(lastlines[ip])

if __name__ == '__main__':
    args = " ".join(x for x in sys.argv[1:])

    rate = 10
    sport = 80
    output_fields = 'timestamp,saddr,ja4ts'
    output_file = 'console'
    dedup_method = 'none'
    dest = None

    parser = argparse.ArgumentParser(
        prog='ja4tscan',
        description='JA4TS scanner built over zmap')

    parser.add_argument('dest', help='destination network (ex, 203.123.123.0/24) ')
    parser.add_argument('-r', '--rate', help='zmap rate (defaults to 10)')
    parser.add_argument('-p', '--port', help='tcp source port (defaults to 80)')
    parser.add_argument('--output-fields', help='zmap output fields (defaults to timestamp,saddr,ja4tscan)')
    parser.add_argument('-o', '--output-file', choices=['console', 'csv'], help='default is set to console and output.csv is also generated')
    parser.add_argument('--retransmit', choices=['yes', 'no'], help='translates to zmap dedup-method, default is yes (dedup-method none)')

    filename = 'output.csv'

    try:
        args = parser.parse_args()
        dest = args.dest
    except Exception as e:
        parser.print_help()

    if args.port:
        sport = args.port
    if args.rate:
        rate = args.rate
    if args.output_fields:
        output_fields = args.output_fields
    if args.output_file:
        output_file = args.output_file
    if args.retransmit and args.retransmit == 'no':
        dedup_method = 'full'

    if dedup_method == 'none': 
        setup_iptables()
        cmd = f"zmap -p {sport} -r {rate} {dest} -o {filename} --output-fields={output_fields} --probe-module=ja4ts --dedup-method {dedup_method} --cooldown-time=10"
        #         --output-filter='classification=rst'"
    else:
        cleanup_iptables()
        cmd = f"zmap -p {sport} -r {rate} {dest} -o {filename} --output-fields={output_fields} --probe-module=ja4ts --dedup-method {dedup_method}"

    try:
        ret = os.system(cmd)
        if ret > 0:
            sys.exit(0)

        post_process_output(filename)
        if output_file == 'console':
            os.system(f"cat {filename}")
    except Exception as e:
        sys.exit(0)

    if dedup_method == 'none': 
        cleanup_iptables()

