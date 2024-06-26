Please read our blogs for details on how JA4+ Network Fingerprinting works, why it works, and examples of what can be detected/prevented with it:  
[JA4+ Network Fingerprinting](https://blog.foxio.io/ja4%2B-network-fingerprinting) (JA4/S/H/L/X/SSH)  
[JA4T: TCP Fingerprinting](https://blog.foxio.io/ja4t-tcp-fingerprinting) (JA4T/TS/TScan)

# JA4TScan

JA4TScan is a probe module for Zmap with a python wrapper that generates TCP server fingerprints with a single SYN packet.  

Inspiration came from p0f (Michał Zalewski), Hershel+ (Zain Shamsi & Dmitri Loguinov), and gait (Charles Smutz & Brandon A. Thomas).

Past TCP fingerprinting tools were designed to fuzzy match with known operating systems. To achieve that, they ignore elements that can change based on network conditions and produced fingerprints that were not meant to be logged or used as pivot points in analysis. 

JA4TScan is designed to highlight unusual network conditions and produce a fingerprint that is both human and machine readable to facilitate more effective hunting and analysis. While still able to identify the OS/Device, JA4TScan also helps to identify intermediary proxies, load balancers, port forwarding, etc.

![JA4T](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.png)

JA4TScan Examples:

| OS/Device/Application | JA4TScan |
|-----|-----|
| Windows 10 | 64240_2-1-3-1-1-4_1460_8_1-2-4-8-R6 |
| Windows 2003 | 16384_2-1-3-1-1-8-1-1-4_1460_00_2-7 |
| Amazon AWS Linux 2 | 62727_2-4-8-1-3_8961_7_1-2-4-8-16 |
| Mac OSX / iPhone | 65535_2-1-3-1-1-8-4-0-0_1460_6_1-2-4-8-16-32-12 |
| F5 Big IP | 4380_2-4-8_1460_0_3-6-12 |
| HP ILO | 5840_2_1460_00_3-6-12-24-48-60-60-60-60-60 |
| Epson Printer | 28960_2-4-8-1-3_1460_3_1-4-8-16 |
| Ubiquiti Router | 43440_2-4-8-1-3_1460_12_1-2-4-8-17 |

Things to think about:  
Most systems have a Maximum Segment Size (MSS) of 1460. A MSS slightly below 1460, such as 1436, suggests a network element in-line before the system. A MSS around 1380 may suggest the traffic is bouncing through a intermediary device. AWS systems use a MSS of 8961. More testing is ongoing to correlate an amount of MSS and Window Size change to corresponding network conditions.

Windows-based systems tend to send a RST packet after several TCP retransmissions, denoted in the fingerprint with a "R". Linux-based systems do not send RST packets.

## Usage

You can use ja4tscan to probe any given network, a single IP, or a list of IP addresses specified in a file.

Example - Probe a network:
`sudo python3 ja4tscan.py -p 80 204.79.197.212/28`

Example Output:
```
1701655215,204.79.197.208,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.209,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.210,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655215,204.79.197.211,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.212,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655217,204.79.197.213,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.214,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.215,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655217,204.79.197.216,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655217,204.79.197.217,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.218,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.219,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655216,204.79.197.220,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655217,204.79.197.221,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655217,204.79.197.222,65535_2-1-3-1-1-4_1440_8_0-1-R2
1701655217,204.79.197.223,65535_2-1-3-1-1-4_1440_8_0-1-R2
```

Example - Probe a single IP:
`sudo python3 ja4tscan.py -p 80 204.79.197.223`

Example Output:
```
1710168119,204.79.197.223,65535_2-1-3-1-1-4_1440_8_0-1-R2
```

Example - Probe a list of IPs:
`sudo python3 ja4tscan.py -p 80 iplist`

Example Input - contents of file "iplist":
```
204.79.197.216
204.79.197.217
204.79.197.212
```
Example Output:
```
1710168610,204.79.197.212,65535_2-1-3-1-1-4_1440_8_0-1-R2
1710168610,204.79.197.216,65535_2-1-3-1-1-4_1440_8_0-1-R2
1710168610,204.79.197.217,65535_2-1-3-1-1-4_1440_8_0-1-R2
```

JA4TScan sends a single SYN packet to each destination and then listens for 2 minutes. The destination will respond with a SYN-ACK packet that includes the destination's TCP options. JA4TScan will not respond to the SYN-ACK but will continue to listen. The destination will retransmit the SYN-ACK multiple times, at different intervals depending on how the code was written for that destination device/OS. JA4TScan captures these retransmissions, the time interval between them (in seconds) and adds them to the fingerprint. 

By default, ja4tscan sets the following attributes while calling zmap
  * `--probe-module` flag specifies the probe module to use as ja4tscan.
  * `--output-fields` flag specifies the fields to include 'timestamp,saddr,ja4tscan' in the output. 
  * `--retransmit` flag is set to "yes" by default, specifying --dedup-method none to be used by zmap.

    When `--dedup-method` is set to `none` retransmission packets are captured. We do this by using iptables to drop RST packets coming from servers. This way, we can receive SYN-ACK retransmitions.

    When the `retransmit` flag is set to "yes", `dedup-method` is set to full. This means the probe will not generate any SYN-ACK retransmits. You will still be able to record JA4TScan fingerprints for SYN packets but without retrasmissions.

## Build Instructions
JA4TScan is currently available for zmap version 4.1.0.

```
# Clone this repo
git clone https://github.com/FoxIO-LLC/ja4tscan

# Run our build script
sudo ./build.sh

# Run JA4TScan with the default mode, i.e., retransmit yes.
sudo python3 ja4tscan.py -p 80 204.79.197.212/28 

# Run without retransmits
sudo python3 ja4tscan.py -p 80 204.79.197.212/28 --retransmit no

# See all options
sudo python3 ja4tscan.py --help
```
## License
JA4TScan is licensed under the FoxIO License 1.1
See [License Information](https://github.com/FoxIO-LLC/ja4?tab=readme-ov-file#licensing) for more details.
