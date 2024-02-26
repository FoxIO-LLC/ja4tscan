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
    parser.add_argument('--output-fields', help='zmap output fields (defaults to timestamp,saddr,ja4tscan')
    parser.add_argument('-o', '--output-file', help='default output goes to output.csv')
    parser.add_argument('--retransmit', choices=['yes', 'no'], help='translates to zmap dedup-method, default is yes (dedup-method none)')

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
        cmd = f"zmap -p {sport} -r {rate} {dest} -o 'output.csv' --output-fields={output_fields} --probe-module=ja4ts --dedup-method {dedup_method}\
                 --output-filter='classification=rst'"
    else:
        cmd = f"zmap -p {sport} -r {rate} {dest} -o 'output.csv' --output-fields={output_fields} --probe-module=ja4ts --dedup-method {dedup_method}"

    try:
        ret = os.system(cmd)
        if ret > 0:
            sys.exit(0)

        if output_file == 'console':
            os.system(f"cat output.csv")
    except Exception as e:
        sys.exit(0)

    if dedup_method == 'none': 
        cleanup_iptables()

