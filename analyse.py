#!/usr/bin/env python3
"""
Log Analysis Script for IEUK 2025 Engineering Sector Skills Project
Analyzes web server log files to extract key information for security and performance insights
"""

import re
import sys
from collections import defaultdict, Counter
from datetime import datetime
import argparse

class LogAnalyzer:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.total_requests = 0
        self.ip_addresses = Counter()
        self.status_codes = Counter()
        self.request_methods = Counter()
        self.user_agents = Counter()
        self.countries = Counter()
        self.hourly_traffic = defaultdict(int)
        self.daily_traffic = defaultdict(int)
        self.suspicious_ips = set()
        self.error_requests = []
        self.large_requests = []
        
        # Common log format pattern - flexible to handle different formats
        # IP - Country - [timestamp] "METHOD /path HTTP/version" status size "referer" "user-agent"
        self.log_pattern = re.compile(
            r'(\d+\.\d+\.\d+\.\d+)\s+-\s+(\w+)\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)(?:\s+(\d+))?(?:\s+"([^"]*)"\s+"([^"]*)")?'
        )
        
    def parse_log_line(self, line):
        """Parse a single log line and extract components"""
        match = self.log_pattern.match(line.strip())
        if not match:
            return None
            
        groups = match.groups()
        ip = groups[0]
        country = groups[1]
        timestamp = groups[2]
        request = groups[3]
        status = groups[4]
        size = groups[5] if len(groups) > 5 and groups[5] else '0'
        referer = groups[6] if len(groups) > 6 and groups[6] else '-'
        user_agent = groups[7] if len(groups) > 7 and groups[7] else '-'
        
        try:
            # Parse timestamp: [01/Jul/2025:06:00:43 +0000]
            timestamp_str = timestamp.split()[0]  # Remove timezone if present
            # Handle different date formats
            for fmt in ['%d/%b/%Y:%H:%M:%S', '%d/%m/%Y:%H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    dt = datetime.strptime(timestamp_str, fmt)
                    break
                except ValueError:
                    continue
            else:
                # If no format works, use current time
                dt = datetime.now()
            
            # Parse request method
            request_parts = request.split()
            method = request_parts[0] if request_parts else 'UNKNOWN'
            path = request_parts[1] if len(request_parts) > 1 else '/'
            
            return {
                'ip': ip,
                'country': country,
                'datetime': dt,
                'method': method,
                'path': path,
                'status': int(status),
                'size': int(size) if size.isdigit() else 0,
                'referer': referer,
                'user_agent': user_agent,
                'request': request
            }
        except (ValueError, IndexError) as e:
            print(f"Error parsing line: {line[:100]}... Error: {e}")
            return None
    
    def is_suspicious_activity(self, parsed_log):
        """Identify potentially suspicious activities"""
        suspicious_indicators = []
        
        # High volume from single IP (checked later)
        # SQL injection attempts
        if any(keyword in parsed_log['path'].lower() for keyword in 
               ['union', 'select', 'drop', 'insert', 'update', 'delete', 'script', 'alert']):
            suspicious_indicators.append('Potential SQL injection/XSS')
            
        # Directory traversal
        if '../' in parsed_log['path'] or '..\\' in parsed_log['path']:
            suspicious_indicators.append('Directory traversal attempt')
            
        # Admin path access
        if any(admin_path in parsed_log['path'].lower() for admin_path in 
               ['/admin', '/wp-admin', '/administrator', '/login', '/config']):
            suspicious_indicators.append('Admin path access')
            
        # Unusual user agents
        if any(bot in parsed_log['user_agent'].lower() for bot in 
               ['bot', 'crawler', 'spider', 'scan']) and 'google' not in parsed_log['user_agent'].lower():
            suspicious_indicators.append('Potential malicious bot')
            
        return suspicious_indicators
    
    def analyze_logs(self):
        """Main analysis function"""
        print("Starting log analysis...")
        print(f"Analyzing file: {self.log_file_path}")
        
        try:
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as file:
                line_count = 0
                for line in file:
                    line_count += 1
                    if line_count % 100000 == 0:
                        print(f"Processed {line_count:,} lines...")
                    
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue
                        
                    self.total_requests += 1
                    
                    # Collect statistics
                    self.ip_addresses[parsed['ip']] += 1
                    self.status_codes[parsed['status']] += 1
                    self.request_methods[parsed['method']] += 1
                    self.user_agents[parsed['user_agent']] += 1
                    self.countries[parsed['country']] += 1
                    
                    # Time-based analysis
                    hour_key = parsed['datetime'].strftime('%Y-%m-%d %H:00')
                    day_key = parsed['datetime'].strftime('%Y-%m-%d')
                    self.hourly_traffic[hour_key] += 1
                    self.daily_traffic[day_key] += 1
                    
                    # Error tracking
                    if parsed['status'] >= 400:
                        self.error_requests.append(parsed)
                    
                    # Large request tracking
                    if parsed['size'] > 1000000:  # > 1MB
                        self.large_requests.append(parsed)
                    
                    # Suspicious activity detection
                    suspicious = self.is_suspicious_activity(parsed)
                    if suspicious:
                        self.suspicious_ips.add(parsed['ip'])
                        
        except FileNotFoundError:
            print(f"Error: File {self.log_file_path} not found")
            return False
        except Exception as e:
            print(f"Error reading file: {e}")
            return False
            
        print(f"Analysis complete. Processed {self.total_requests:,} total requests")
        return True
    
    def identify_high_volume_ips(self, threshold=1000):
        """Identify IPs with unusually high request volumes"""
        high_volume_ips = {ip: count for ip, count in self.ip_addresses.items() 
                          if count > threshold}
        return high_volume_ips
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "="*80)
        print("LOG ANALYSIS REPORT")
        print("="*80)
        
        # Basic statistics
        print(f"\n📊 BASIC STATISTICS")
        print(f"Total Requests: {self.total_requests:,}")
        print(f"Unique IP Addresses: {len(self.ip_addresses):,}")
        print(f"Unique Countries: {len(self.countries):,}")
        if self.daily_traffic:
            print(f"Date Range: {min(self.daily_traffic.keys())} to {max(self.daily_traffic.keys())}")
        else:
            print("Date Range: No valid dates found")
        
        # Top IPs
        print(f"\n🌐 TOP 10 IP ADDRESSES")
        for ip, count in self.ip_addresses.most_common(10):
            percentage = (count / self.total_requests) * 100
            print(f"{ip:<15} {count:>8,} requests ({percentage:>5.1f}%)")
        
        # Status codes
        print(f"\n📈 HTTP STATUS CODES")
        for status, count in sorted(self.status_codes.items()):
            percentage = (count / self.total_requests) * 100
            status_desc = {
                200: "OK", 301: "Moved Permanently", 302: "Found", 
                404: "Not Found", 403: "Forbidden", 500: "Internal Server Error"
            }.get(status, "Other")
            print(f"{status} {status_desc:<20} {count:>8,} ({percentage:>5.1f}%)")
        
        # Request methods
        print(f"\n🔧 REQUEST METHODS")
        for method, count in self.request_methods.most_common():
            percentage = (count / self.total_requests) * 100
            print(f"{method:<8} {count:>8,} ({percentage:>5.1f}%)")
        
        # Countries
        print(f"\n🌍 TOP 10 COUNTRIES")
        for country, count in self.countries.most_common(10):
            percentage = (count / self.total_requests) * 100
            print(f"{country:<3} {count:>8,} requests ({percentage:>5.1f}%)")
        
        # High volume IPs (potential DDoS or bot activity)
        high_volume = self.identify_high_volume_ips(1000)
        if high_volume:
            print(f"\n⚠️  HIGH VOLUME IP ADDRESSES (>1000 requests)")
            for ip, count in sorted(high_volume.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.total_requests) * 100
                print(f"{ip:<15} {count:>8,} requests ({percentage:>5.1f}%) - POTENTIAL THREAT")
        
        # Error analysis
        error_count = sum(1 for status in self.status_codes if status >= 400)
        if error_count > 0:
            print(f"\n❌ ERROR ANALYSIS")
            print(f"Total Error Requests: {error_count:,}")
            error_rate = (error_count / self.total_requests) * 100
            print(f"Error Rate: {error_rate:.2f}%")
            
            if self.error_requests:
                print("Top Error-generating IPs:")
                error_ips = Counter(req['ip'] for req in self.error_requests[-1000:])  # Last 1000 errors
                for ip, count in error_ips.most_common(5):
                    print(f"  {ip:<15} {count:>3} errors")
        
        # Suspicious activity
        if self.suspicious_ips:
            print(f"\n🚨 SECURITY ALERTS")
            print(f"Suspicious IP Addresses Detected: {len(self.suspicious_ips)}")
            for ip in list(self.suspicious_ips)[:10]:  # Show first 10
                request_count = self.ip_addresses[ip]
                print(f"  {ip:<15} {request_count:>5} requests - REQUIRES INVESTIGATION")
        
        # Traffic patterns
        print(f"\n📅 DAILY TRAFFIC PATTERNS")
        sorted_days = sorted(self.daily_traffic.items())
        for day, count in sorted_days[-7:]:  # Last 7 days
            print(f"{day} {count:>8,} requests")
        
        if len(sorted_days) > 1:
            avg_daily = sum(self.daily_traffic.values()) / len(self.daily_traffic)
            print(f"Average Daily Requests: {avg_daily:,.0f}")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS")
        
        if high_volume:
            print("• Implement rate limiting for high-volume IP addresses")
            print("• Consider blocking or monitoring IPs with >10,000 requests/day")
        
        if self.suspicious_ips:
            print("• Investigate suspicious IP addresses for potential security threats")
            print("• Review firewall rules and access controls")
        
        error_rate = (sum(1 for status in self.status_codes if status >= 400) / self.total_requests) * 100
        if error_rate > 5:
            print(f"• High error rate ({error_rate:.1f}%) - investigate server issues")
        
        print("• Regular log monitoring should be implemented")
        print("• Consider implementing intrusion detection systems")
        
        print("\n" + "="*80)
        print("END OF REPORT")
        print("="*80)

def main():
    parser = argparse.ArgumentParser(description='Analyze web server log files')
    parser.add_argument('logfile', nargs='?', 
                       default='sample-log.log',
                       help='Path to the log file to analyze')
    
    args = parser.parse_args()
    
    # Use the provided log file or default
    log_file = args.logfile
    
    print("IEUK 2025 Engineering Sector Skills Project")
    print("Web Server Log Analysis Tool")
    print("-" * 50)
    
    analyzer = LogAnalyzer(log_file)
    
    if analyzer.analyze_logs():
        analyzer.generate_report()
    else:
        print("Analysis failed. Please check the log file path and format.")
        sys.exit(1)

if __name__ == "__main__":
    main()