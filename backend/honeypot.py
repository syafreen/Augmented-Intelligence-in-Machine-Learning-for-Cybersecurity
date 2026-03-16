import socket
import time
import random

from config import (
    logger,
    HONEYPOT_ENABLED,
    HONEYPOT_API_KEY,
    HONEYPOT_CACHE_DURATION,
    HONEYPOT_TIMEOUT,
    HONEYPOT_THRESHOLDS,
)
from typing import Optional, Dict, Any

"""
Honeypot integration.
Performs IP reputation checks via Project Honey Pot DNS service and
provides realistic IP address generation utilities.
"""

ip_reputation_cache = {}


def check_ip_reputation(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Check IP reputation using Project Honey Pot HTTP:BL DNS service.
    
    Args:
        ip_address: IP address to check (e.g., "192.168.1.1")
    
    Returns:
        dict with reputation data or None if not found/error
    """
    if not HONEYPOT_ENABLED or not HONEYPOT_API_KEY:
        return None
    
    # Check cache first
    if ip_address in ip_reputation_cache:
        cached_result, timestamp = ip_reputation_cache[ip_address]
        if time.time() - timestamp < HONEYPOT_CACHE_DURATION:
            return cached_result
    
    try:
        # Reverse the IP octets for DNS lookup
        reversed_ip = '.'.join(ip_address.split('.')[::-1])
        
        # Construct DNS query: {API_KEY}.{reversed_IP}.dnsbl.httpbl.org
        query = f"{HONEYPOT_API_KEY}.{reversed_ip}.dnsbl.httpbl.org"
        
        # Set DNS timeout
        socket.setdefaulttimeout(HONEYPOT_TIMEOUT)
        
        try:
            # Perform DNS lookup
            result = socket.gethostbyname(query)
            
            # Parse response: 127.{days}.{threat_score}.{type}
            octets = result.split('.')
            
            if octets[0] == '127':
                days_since = int(octets[1])
                threat_score = int(octets[2])
                visitor_type = int(octets[3])
                
                # X = days since last activity
                # Y = threat score (0-255)
                # Z = visitor type
                visitor_types = []
                if visitor_type & 1:
                    visitor_types.append('Suspicious')
                if visitor_type & 2:
                    visitor_types.append('Harvester')
                if visitor_type & 4:
                    visitor_types.append('Comment Spammer')
                if visitor_type == 0:
                    visitor_types.append('Search Engine')
                
                # Map threat score to level
                threat_thresholds = HONEYPOT_THRESHOLDS or {
                    'critical': 200,
                    'high': 100,
                    'medium': 50,
                    'low': 25
                }
                
                if threat_score >= threat_thresholds.get('critical', 200):
                    threat_level = 'Critical'
                elif threat_score >= threat_thresholds.get('high', 100):
                    threat_level = 'High'
                elif threat_score >= threat_thresholds.get('medium', 50):
                    threat_level = 'Medium'
                elif threat_score >= threat_thresholds.get('low', 25):
                    threat_level = 'Low'
                else:
                    threat_level = 'Clean'
                
                reputation_data = {
                    'ip': ip_address,
                    'is_threat': threat_score >= threat_thresholds.get('low', 25),
                    'threat_score': threat_score,
                    'threat_level': threat_level,
                    'days_since_last_activity': days_since,
                    'visitor_types': visitor_types,
                    'raw_response': result,
                    'source': 'Project Honey Pot'
                }
                
                # Cache the result
                ip_reputation_cache[ip_address] = (reputation_data, time.time())
                
                logger.debug(f"IP Reputation: {ip_address} -> Score: {threat_score}, Level: {threat_level}")
                return reputation_data
            else:
                # Not in database - IP is clean
                clean_result = {
                    'ip': ip_address,
                    'is_threat': False,
                    'threat_score': 0,
                    'threat_level': 'Clean',
                    'days_since_last_activity': None,
                    'visitor_types': [],
                    'raw_response': result,
                    'source': 'Project Honey Pot'
                }
                ip_reputation_cache[ip_address] = (clean_result, time.time())
                return clean_result
                
        except socket.gaierror:
            # DNS lookup failed - IP not in database (clean)
            clean_result = {
                'ip': ip_address,
                'is_threat': False,
                'threat_score': 0,
                'threat_level': 'Clean',
                'days_since_last_activity': None,
                'visitor_types': [],
                'raw_response': None,
                'source': 'Project Honey Pot (not found)'
            }
            ip_reputation_cache[ip_address] = (clean_result, time.time())
            return clean_result
            
        except socket.timeout:
            logger.warning(f"Timeout checking IP reputation for {ip_address}")
            return None
            
    except Exception as e:
        logger.warning(f"Error checking IP reputation for {ip_address}: {e}")
        return None



def generate_realistic_ip(attack_type: str) -> str:
    """
    Generate a realistic IP address based on attack type.
    Uses IP ranges commonly associated with different attack types.
    
    Args:
        attack_type: Type of attack (DDoS, PortScan, etc.)
    
    Returns:
        str: IP address
    """
    # IP ranges associated with different attack types
    # These are commonly seen in threat intelligence feeds
    attack_ip_ranges = {
        'DDoS': [
            (185, 0, 255), (91, 0, 255), (194, 0, 255),
            (103, 0, 255), (45, 0, 255), (5, 0, 255)
        ],
        'PortScan': [
            (192, 168, 255), (10, 0, 255), (172, 16, 31),
            (141, 0, 255), (159, 0, 255), (195, 0, 255)
        ],
        'Web Attack ⚔ Brute Force': [
            (31, 0, 255), (37, 0, 255), (178, 0, 255),
            (95, 0, 255), (46, 0, 255)
        ],
        'Web Attack ⚔ XSS': [
            (62, 0, 255), (78, 0, 255), (91, 0, 255),
            (188, 0, 255)
        ],
        'Web Attack ⚔ Sql Injection': [
            (31, 0, 255), (37, 0, 255), (178, 0, 255),
            (95, 0, 255)
        ],
        'Bot': [
            (5, 0, 255), (45, 0, 255), (185, 0, 255),
            (194, 0, 255), (103, 0, 255)
        ],
        'Infiltration': [
            (10, 0, 255), (172, 16, 31), (192, 168, 255),
            (203, 0, 255)
        ]
    }
    
    # Get IP range for attack type
    ranges = attack_ip_ranges.get(attack_type, [
        (192, 0, 255), (185, 0, 255), (91, 0, 255)
    ])
    
    # Pick a random range
    selected_range = random.choice(ranges)
    
    # Generate IP within range
    octet1 = selected_range[0]
    octet2 = random.randint(selected_range[1], selected_range[2]) if selected_range[1] != selected_range[2] else selected_range[1]
    octet3 = random.randint(0, 255)
    octet4 = random.randint(1, 254)
    
    return f"{octet1}.{octet2}.{octet3}.{octet4}"
