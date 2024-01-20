# OntyFire

## Overview
OntyFire is a tool for detecting and alerting users to potential Man-in-the-Middle (MitM) attacks on their network. MitM attacks involve intercepting and possibly altering communication between two parties without their knowledge.

It continuously monitors network traffic, and raises alerts when unusual behavior is detected , when discrepancy found in mac address.

## Features
Real-time Monitoring: The detector actively monitors network traffic to identify anomalies in communication patterns.

ARP Spoofing Detection: Detects Address Resolution Protocol (ARP) spoofing attacks by analyzing changes in MAC addresses associated with IP addresses.

DNS Spoofing Detection: Identifies potential Domain Name System (DNS) spoofing by analyzing discrepancies in DNS responses.

Alerts and Notifications: Notifies users through console when suspicious activity is detected.

## Installation
Clone the repository:

- git clone https://github.com/MedAmyyne/MITM_Detector.git
  
Install dependencies:

- pip3 install -r requirements.txt
  

## Help
- python3 OntyFire.py --help / -h

## Usage
- python3 OntyFire.py -i < interface_either_wlan0_or_eth0>

## Contributing
Contributions are welcome! Feel free to open issues, submit pull requests, or suggest improvements. Please follow the code of conduct in all interactions.
