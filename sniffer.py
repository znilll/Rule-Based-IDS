import time
from scapy.all import rdpcap, TCP, IP, ICMP, DNS, Raw, sniff
from collections import defaultdict, deque
import urllib.parse
import tkinter as tk
from tkinter import scrolledtext
import threading

# Define the destination IP address
DEST_IP = '127.0.0.1'

# Define the list of event handlers as a constant
EVENT_HANDLERS = [
    'onmouseenter', 'onclick', 'onload', 'onfocus', 'onblur',
    'onkeypress', 'onkeydown', 'onkeyup', 'onsubmit', 'onchange', 'onselect',
    'ondblclick', 'oncontextmenu', 'onstart', 'onerror', 'onabort', 'onunload',
    'onmove', 'onresize', 'onscroll', 'ondrag', 'ondragend', 'ondragenter',
    'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onkeydown',
    'onkeypress', 'onkeyup', 'onload', 'onmousedown', 'onmousemove',
    'onmouseout', 'onmouseup', 'onreset', 'onresize',
    'onscroll', 'onselect', 'onsubmit', 'onunload', 'onclick', 'ondblclick', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
    'onkeydown', 'onkeypress', 'onkeyup', 'onabort', 'onbeforeunload', 'onerror', 'onhashchange',
    'onload', 'onpageshow', 'onpagehide', 'onresize', 'onscroll', 'onunload', 'onblur', 'onchange',
    'oncontextmenu', 'onfocus', 'oninput', 'oninvalid', 'onreset', 'onsearch', 'onselect', 'onsubmit',
    'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop',
    'oncopy', 'oncut', 'onpaste', 'onafterprint', 'onbeforeprint', 'oncanplay', 'oncanplaythrough',
    'ondurationchange', 'onemptied', 'onended', 'onloadeddata', 'onloadedmetadata', 'onloadstart',
    'onpause', 'onplay', 'onplaying', 'onprogress', 'onratechange', 'onseeked', 'onseeking',
    'onstalled', 'onsuspend', 'ontimeupdate', 'onvolumechange', 'onwaiting', 'ontoggle', 'onwheel',
    'onauxclick', 'ongotpointercapture', 'onlostpointercapture', 'onpointerdown', 'onpointermove',
    'onpointerup', 'onpointercancel', 'onpointerover', 'onpointerout', 'onpointerenter', 'onpointerleave',
    'onselectstart', 'onselectionchange', 'onshow', 'ontouchcancel', 'ontouchend', 'ontouchmove',
    'ontouchstart', 'ontransitionend', 'onanimationstart', 'onanimationend', 'onanimationiteration',
    'onbeforeinput', 'onformdata', 'onpointerlockchange', 'onpointerlockerror', 'onreadystatechange',
    'onvisibilitychange'
]


# Define the list of potential XSS content as a global constant
XSS_CONTENT = [
    '<html', '<script', '<marquee', '<javascript', '<applet', '<object',
    '<embed', '<iframe', '<frame', '<frameset', '<layer', '<bgsound', '<link',
    '<style', '<meta', '<base', '<form', '<input', '<button', '<textarea',
    '<select', '<option', '<img', '<audio', '<video', '<svg', '<math',
    '<canvas', '<noscript', '<plaintext', '<xmp', '<title', '<body',
    '<head', '<basefont', '<isindex', '<keygen', '<listing', '<nextid',
    '<noembed', '<noframes', '<param', '<spacer', '<xml', '<blink',
    '<ilayer', '<nolayer', '<scriptlet', '<xml', '<comment', '<iframe',
    '<object', '<embed', '<applet', '<meta', '<link', '<style', '<base',
    '<form', '<input', '<button', '<textarea', '<select', '<option',
    '<img', '<audio', '<video', '<svg', '<math', '<canvas', '<noscript',
    '<plaintext', '<xmp', '<title', '<body', '<head', '<basefont',
    '<isindex', '<keygen', '<listing', '<nextid', '<noembed', '<noframes',
    '<param', '<spacer', '<xml', '<blink', '<ilayer', '<nolayer',
    '<scriptlet', '<xml', '<comment'
]

SQL_INJECTION_CONTENT = [
    'select', 'null', 'insert', 'update', 'delete', 'drop', 'union', 'alter', 'create',
    'exec', 'execute', 'grant', 'revoke', 'truncate', 'declare', 'cast',
    'convert', 'set', 'show', 'describe', 'explain', 'commit', 'rollback',
    'savepoint', 'release', 'lock', 'unlock', 'call', 'prepare', 'execute',
    'fetch', 'open', 'close', 'deallocate', 'cursor', 'procedure', 'function',
    'trigger', 'view', 'index', 'table', 'column', 'database', 'schema',
    'else', 'end', 'begin', 'while', 'loop', 'for',  'case', 'when',
    'then', 'else', 'end', 'and', 'not', 'null', 'like',
    'between', 'exists', 'all', 'any', 'some', 'distinct', 'group', 'by',
    'having', 'order', 'asc', 'desc', 'limit', 'offset', 'fetch', 'first',
    'next', 'row', 'rows', 'only', 'into', 'values', 'set', 'where', 'join',
    'outer', 'left', 'right', 'full', 'cross', 'natural', 'using',
    'with', 'as', 'alias', 'from', 'to', 'by', 'with', 'without',
    'partition', 'range', 'rows', 'preceding', 'following', 'current',
    'row', 'unbounded', 'preceding', 'following', 'current', 'row', 'unbounded',
    '--', '#', '-- ', '1=1', 'or 1=1', 'or 1=1--',
    'or 1=1/*', 'or 1=1#', 'or 1=1;', 'do', 'all', 'end'
]

def to_lower(value):
    return value.lower()

def load_rules(rule_file):
    rules = []
    with open(rule_file, 'r') as file:
        for line in file:
            # Replace the placeholder with the actual destination IP
            line = line.replace('{DEST_IP}', DEST_IP)
            parts = line.strip().split(', ')
            if len(parts) >= 6:
                rule = {
                    'name': parts[0],
                    'protocol': parts[1],
                    'src_ip': parts[3],
                    'dst_ip': parts[4],
                    'dst_port_range': parts[5],
                    'dns_flags': 'any'  # Initialize dns_flags with a default value
                }
                
                # Determine the specific field based on the protocol
                if rule['protocol'] == 'HTTP':
                    rule['method'] = parts[2]  # Capture HTTP method
                elif rule['protocol'] == 'TCP':
                    rule['flag'] = parts[2]  # Capture TCP flag
                elif rule['protocol'] == 'ICMP':
                    rule['icmp_type'] = parts[2]  # Capture ICMP type
                elif rule['protocol'] == 'DNS':
                    if parts[2] == 'any':
                        rule['dns_flags'] = 'any'
                    else:
                        rule['dns_flags'] = int(parts[2], 16)  # Capture DNS flags as hex

                for part in parts[6:]:
                    if '=' in part:
                        key, value = part.split('=')
                        if key == 'ratio':
                            rule[key] = float(value)
                        elif key == 'is_unique':
                            rule[key] = int(value)
                        elif key == 'len':
                            if value == 'any':
                                rule[key] = 'any'  # Keep 'any' as a string
                            else:
                                rule[key] = int(value)
                        elif key == 'pps':
                            rule[key] = int(value)
                    else:
                        print(f"Warning: Skipping invalid rule part '{part}' in line: {line.strip()}")
                rules.append(rule)
    return rules

def extract_features(packet):
    features = {}
    known_protocol = False  # Flag to track if a known protocol is found

    if packet.haslayer(IP):
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        known_protocol = True

    if packet.haslayer(TCP):
        features['src_port'] = packet[TCP].sport
        features['dst_port'] = packet[TCP].dport
        features['flags'] = packet[TCP].flags
        known_protocol = True


    if packet.haslayer(ICMP):
        features['icmp_type'] = packet[ICMP].type
        features['icmp_code'] = packet[ICMP].code
        known_protocol = True

    if packet.haslayer(DNS):
        dns_layer = packet[DNS]
        # Construct the DNS flags from individual fields
        features['dns_flags'] = (
            (dns_layer.qr << 15) |
            (dns_layer.opcode << 11) |
            (dns_layer.aa << 10) |
            (dns_layer.tc << 9) |
            (dns_layer.rd << 8) |
            (dns_layer.ra << 7) |
            (dns_layer.z << 4) |
            dns_layer.rcode
        )
        known_protocol = True

    if packet.haslayer(Raw):  # Assuming HTTP content is in Raw layer
        payload = to_lower(packet[Raw].load.decode(errors='ignore'))
        # Check for HTTP methods only if the payload starts with a known HTTP method
        if payload.startswith(('get', 'post', 'put', 'delete', 'head', 'options', 'patch', 'trace')):
            known_protocol = True
            features['method'] = payload.split()[0].upper()  # Capture the HTTP method
            decoded_content = urllib.parse.unquote(payload)
            features['content'] = decoded_content

            found_content = [content for content in XSS_CONTENT if content in decoded_content]
            features['found_content'] = found_content
            found_handlers = [handler for handler in EVENT_HANDLERS if handler in decoded_content]
            features['found_handlers'] = found_handlers
            found_sql = [sql for sql in SQL_INJECTION_CONTENT if sql in decoded_content]
            features['found_sql'] = found_sql

    features['len'] = len(packet)  # Add packet length

    if not known_protocol:
        features['unknown_protocol'] = True  # Mark as unknown protocol

    return features

def match_rule(features, rule, packet_id):
    criteria_matched = []
    criteria_unmatched = []

    # Check protocol and flags
    if rule['protocol'] == 'TCP' and 'flags' in features:
        criteria_matched.append(f"Protocol matches: {rule['protocol']}")

        # Check for RST/ACK flags
        if rule['flag'] == 'RST/ACK':
            if (features['flags'] & 0x14) == 0x14:  # 0x14 is the bitmask for RST and ACK
                criteria_matched.append('RST/ACK flags detected')
            else:
                criteria_unmatched.append('RST/ACK flags not detected')

        # Check for SYN flag
        if rule['flag'] == 'SYN':
            if (features['flags'] & 0x02):  # SYN flag
                criteria_matched.append('SYN flag set')
            else:
                criteria_unmatched.append('SYN flag not set')

    elif rule['protocol'] == 'HTTP' and 'method' in features:
        criteria_matched.append(f"Protocol matches: {rule['protocol']}")
        if 'method' in rule and rule['method'] == 'GET' and 'content' in features:
            # Check for XSS content using the global XSS_CONTENT list
            if rule['name'] == 'XSS':
                matched_content = False
                for content in XSS_CONTENT:
                    if content in features.get('found_content', []):
                        criteria_matched.append(f"Content matches {features['found_content']}")
                        matched_content = True
                        break
                if not matched_content:
                    criteria_unmatched.append("No matching XSS content found")
                    
                matched_handler = False
                for event_handler in EVENT_HANDLERS:
                    if event_handler in features.get('found_handlers', []):
                        criteria_matched.append(f"Event handler matches: {features['found_handlers']}")
                        matched_handler = True
                        break
                if not matched_handler:
                    criteria_unmatched.append("No matching event handler found")

            # Check for SQL Injection content using the global SQL_INJECTION_CONTENT list
            elif rule['name'] == 'SQL_INJECTION':
                sql_injection = False
                for sql_content in SQL_INJECTION_CONTENT:
                    if sql_content in features.get('found_sql', []):
                        criteria_matched.append(f"SQL content matches {features['found_sql']}")
                        sql_injection = True
                        break
                if not sql_injection:
                    criteria_unmatched.append("No matching SQL Injection content found")

    elif rule['protocol'] == 'ICMP' and 'icmp_type' in features:
        criteria_matched.append(f"Protocol matches: {rule['protocol']}")
        if 'icmp_type' in rule and features['icmp_type'] != int(rule['icmp_type']):
            criteria_unmatched.append('ICMP type does not match')
        else:
            criteria_matched.append('ICMP type matches')

        if 'icmp_code' in rule and features['icmp_code'] != int(rule['icmp_code']):
            criteria_unmatched.append('ICMP code does not match')
        else:
            criteria_matched.append('ICMP code matches')

    elif rule['protocol'] == 'DNS' and 'dns_flags' in features:
        criteria_matched.append(f"Protocol matches: {rule['protocol']}")
        if 'dns_flags' in rule:
            if features['dns_flags'] != rule['dns_flags']:
                criteria_unmatched.append(f'DNS flags do not match {rule["dns_flags"]}')
            else:
                criteria_matched.append(f'DNS flags match {rule["dns_flags"]}')

    # Check source IP
    if 'src_ip' in rule and rule['src_ip'] != 'any' and features.get('src_ip') != rule['src_ip']:
        criteria_unmatched.append('Source IP does not match')
    else:
        criteria_matched.append('Source IP matches')

    # Check destination IP
    if 'dst_ip' in rule and rule['dst_ip'] != 'any' and features.get('dst_ip') != rule['dst_ip']:
        criteria_unmatched.append('Destination IP does not match')
    else:
        criteria_matched.append('Destination IP matches')

    # Check destination port range
    if 'dst_port_range' in rule:
        port_range = rule['dst_port_range']
        dst_port = features.get('dst_port')

        try:
            if port_range == 'any':
                criteria_matched.append('Destination port is any')
            elif '-' in port_range:
                lower_bound, upper_bound = map(int, port_range.split('-'))
                if not (lower_bound <= dst_port <= upper_bound):
                    criteria_unmatched.append(f'Destination port not in range {port_range}')
                else:
                    criteria_matched.append(f'Destination port in range {port_range}')
            else:
                if dst_port != int(port_range):
                    criteria_unmatched.append(f'Destination port does not match {port_range}')
                else:
                    criteria_matched.append(f'Destination port matches {port_range}')
        except ValueError as e:
            criteria_unmatched.append(f"Invalid port range: {port_range}")
            print(f"Error parsing port range: {e}")

    # Check packet length
    packet_length = features.get('len')
    expected_length = rule.get('len', 'any')  # Default to 'any' if 'len' is not specified in the rule

    if expected_length != 'any' and packet_length != int(expected_length):
        criteria_unmatched.append(f'Packet length does not match expected {expected_length}')
    else:
        criteria_matched.append(f'Packet length matches expected {expected_length} for {rule["name"]}')

    # Ensure that the rule is only matched if the required features are present
    if not criteria_matched:
        return False, criteria_matched, criteria_unmatched

    return True, criteria_matched, criteria_unmatched

class PacketProcessor:
    def __init__(self, rules, master, timeout_duration=2, pps_window_size=50):
        self.rules = rules
        self.master = master
        self.timeout_duration = timeout_duration
        self.pps_window_size = pps_window_size
        self.sniffing = False  # Add a flag to control sniffing
        self.pps_windows = defaultdict(lambda: defaultdict(lambda: deque(maxlen=pps_window_size)))
        self.attack_windows = defaultdict(lambda: defaultdict(lambda: deque(maxlen=pps_window_size)))
        self.label_counts = defaultdict(int)
        self.attack_counts = defaultdict(lambda: defaultdict(int))
        self.start_times = defaultdict(lambda: None)
        self.unique_ips = defaultdict(set)
        self.ongoing_attacks = defaultdict(bool)
        self.packet_id = 0
        self.update_output = lambda message: None  # Initialize to a no-op function

    def process_packet(self, packet):
        if not self.sniffing:  # Check if sniffing is stopped
            return
        self.packet_id += 1
        features = extract_features(packet)

        # Skip packets with unknown protocols
        if features.get('unknown_protocol', False):
            print("Unknown protocol, skipping.")
            return

        # Ensure dst_port, dst_ip, and src_ip are present
        features['dst_port'] = features.get('dst_port', 0)
        features['dst_ip'] = features.get('dst_ip', 'unknown')
        features['src_ip'] = features.get('src_ip', 'unknown')

        matched_rules = []
        criteria_unmatched = []

        for rule in self.rules:
            # Protocol-based rule selection
            if rule['protocol'] == 'TCP' and not packet.haslayer(TCP):
                continue
            elif rule['protocol'] == 'ICMP' and not packet.haslayer(ICMP):
                continue
            elif rule['protocol'] == 'DNS' and not packet.haslayer(DNS):
                continue
            elif rule['protocol'] == 'HTTP' and not packet.haslayer(Raw):
                continue

            match, criteria_matched, criteria_unmatched = match_rule(features, rule, self.packet_id)
            if match and not criteria_unmatched:  # Only add if there are no unmatched criteria
                matched_rules.append((rule, criteria_matched, criteria_unmatched))

        # Filter XSS and SQL Injection rules
        matched_rules = [
            (rule, criteria_matched, criteria_unmatched) for rule, criteria_matched, criteria_unmatched in matched_rules
            if not (
                (rule['name'] == 'XSS' and not (features.get('found_content', []) or features.get('found_handlers', []))) or
                (rule['name'] == 'SQL_INJECTION' and not features.get('found_sql', []))
            )
        ]
        
        best_rule = None
        max_criteria_matched = 0

        #for rule, _, _ in matched_rules:
            #print(f"Packet ID: {self.packet_id}, Matched Rule: {rule['name']}")

        for rule, criteria_matched, criteria_unmatched in matched_rules:
            is_unique = rule.get('is_unique', 0)
            criteria_count = len(criteria_matched)
            if is_unique:
                if features['src_ip'] not in self.unique_ips[rule['name']]:
                    self.unique_ips[rule['name']].add(features['src_ip'])
                    criteria_matched.append(f"Unique IP: {features['src_ip']}")
                    criteria_count = len(criteria_matched)
                else:
                    criteria_unmatched.append(f"IP {features['src_ip']} is not unique")
                    continue  # Skip if the IP is not unique

            # Increment packet count for the destination IP
            self.attack_counts[rule['name']][features['dst_ip']] += 1
            # Store the current packet's timestamp in the attack window as a tuple
            self.attack_windows[rule['name']][features['dst_ip']].append((self.packet_id, packet.time))
            #print(f"Added Packet ID: {self.packet_id} to attack_windows for rule: {rule['name']}")
            
            time_diff = None
            #print("attack_windows", self.attack_windows)
            # Calculate PPS using the last packet's timestamp
            if len(self.attack_windows[rule['name']][features['dst_ip']]) > 1:  # Ensure there are at least two entries
                last_entry = self.attack_windows[rule['name']][features['dst_ip']][-2]  # Get the second last entry
                last_time = last_entry[1]  # Access the timestamp from the tuple
                time_diff = packet.time - last_time  # Calculate time difference
                #print("current_time", packet.time, "last_time", last_time)
                #print("time diff:", time_diff)
                
                if time_diff > 0:  # Avoid division by zero
                    pps = 1 / time_diff  # Calculate instantaneous PPS
                    #print(f"packet_id: {self.packet_id}, Rule: {rule['name']}, time_diff: {time_diff:.6f} seconds, Instant PPS: {pps:.2f} packets per second")
                else:
                    pps = 0.00
            else:
                pps = 0.00  # Default to 0 if not enough packets
                
        
            rule_pps = rule.get('pps', 0)

            if rule_pps > 0 and time_diff is not None:
                # Initialize start time if not already set
                if self.start_times[rule['name']] is None:
                    self.start_times[rule['name']] = packet.time

                # Calculate time difference from the start time
                elapsed_time = packet.time - self.start_times[rule['name']]


                self.pps_windows[rule['name']][features['dst_ip']].append(pps)
                avg_pps = sum(self.pps_windows[rule['name']][features['dst_ip']]) / len(self.pps_windows[rule['name']][features['dst_ip']])
                print(f"Packet ID: {self.packet_id}, Calculated AVG_PPS: {avg_pps:.2f}")

                if avg_pps >= rule_pps:
                    criteria_matched.append(f"High calculated Avg PPS: {avg_pps:.2f} packets per second\n    - Normal PPS: {rule_pps:.2f} packets per second")
                    if len(criteria_matched) > max_criteria_matched:
                        max_criteria_matched = len(criteria_matched)
                        best_rule = rule
                        best_criteria_matched = criteria_matched  # Update best matched criteria
                else:
                    criteria_unmatched.append(f"Avg PPS {avg_pps:.2f} is below normal PPS {rule_pps:.2f}")
                    continue  # Skip if PPS condition is not met

            else:
                # If no PPS requirement, consider the rule based on other criteria
                if criteria_count > max_criteria_matched:
                    max_criteria_matched = criteria_count
                    best_rule = rule

        # Determine best rule and label the packet
        if best_rule:
            label = best_rule['name']
        else:
            label = 'BENIGN'

        output_message = f"Packet ID: {self.packet_id} labeled as: {label}"
        # print(output_message)
        self.master.after(0, self.update_output, output_message)  # Schedule GUI update

        # Count the label
        self.label_counts[label] += 1

    def sniff_packets(self, interface, update_callback):
        self.sniffing = True  # Set sniffing to True when starting
        self.update_output = update_callback
        sniff(iface=interface, prn=self.process_packet, filter=f"dst host {DEST_IP}")

    def stop_sniffing(self):
        self.sniffing = False  # Set sniffing to False to stop processing packets

class PacketSnifferGUI:
    def __init__(self, master, processor):
        self.master = master
        self.processor = processor
        self.master.title("Packet Sniffer")
        
        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        self.output_area = scrolledtext.ScrolledText(master, width=80, height=20)
        self.output_area.pack(pady=10)

        self.sniffing = False

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_area.delete(1.0, tk.END)  # Clear previous output
        threading.Thread(target=self.processor.sniff_packets, args=('Loopback Pseudo-Interface 1', self.update_output)).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.processor.stop_sniffing()  # Call the stop method in PacketProcessor
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def update_output(self, message):
        self.output_area.insert(tk.END, message + '\n')
        self.output_area.see(tk.END)  # Scroll to the end

# Usage
root = tk.Tk()  # Create the Tkinter root window first
rules = load_rules('rule_based/rules/rules.txt')
processor = PacketProcessor(rules, root)  # Pass the root reference here

app = PacketSnifferGUI(root, processor)
root.mainloop()
