# Rule-Based-IDS

sniffer.py is a basic rule-based IDS built using Python and the Scapy library. It captures network packets, analyzes their contents, and detects potential security threats such as Cross-Site Scripting (XSS), SQL Injection, DoS, DDoS, and Scanning attacks. The application features a graphical user interface (GUI) built with Tkinter, allowing users to start and stop packet sniffing easily.

Key Features
Packet Capture: Utilizes Scapy to capture packets from a specified network interface.

Protocol Analysis: Supports analysis of various protocols, including TCP, ICMP, DNS, and HTTP.

Rule-Based Detection: Implements a rule-based system to identify potential security threats based on predefined rules.

XSS and SQL Injection Detection: Scans packet contents for known patterns associated with XSS and SQL Injection attacks.

User Interface: Provides a simple GUI for user interaction, allowing users to start and stop sniffing and view output in real time.

Components
Imports: The script imports necessary libraries, including Scapy for packet manipulation, Tkinter for the GUI, and collections for data management.

Constants:
DEST_IP: The destination IP address for filtering packets.

EVENT_HANDLERS: A list of common JavaScript event handlers to check for potential XSS attacks.

XSS_CONTENT: A list of HTML tags and attributes commonly used in XSS attacks.

SQL_INJECTION_CONTENT: A list of SQL keywords and patterns used to identify SQL Injection attempts.

Functions:
to_lower(value): Converts a string to lowercase.

load_rules(rule_file): Loads detection rules from a specified file and prepares them for analysis.

extract_features(packet): Extracts relevant features from captured packets for analysis.

match_rule(features, rule, packet_id): Compares extracted features against defined rules to determine matches.

Classes:
PacketProcessor: Handles the processing of captured packets, including feature extraction, rule matching, and maintaining statistics on detected attacks.

PacketSnifferGUI: Manages the GUI components, allowing users to start and stop packet sniffing and display output.

Usage: The script initializes the Tkinter GUI and starts the packet sniffing process using the specified rules loaded from a file.

How to Run
1. Ensure you have Python and installed the required libraries (Scapy, Tkinter).
2. Place your detection rules in a file named rules.txt in the rule_based/rules/ directory.
