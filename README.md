# IEUK 2025 Engineering Sector Skills Project
## Server Log Analysis for Music Media Startup

### Project Overview
This project analyzes server logs to identify and address bot traffic issues affecting a small music media startup's website performance.

### Problem Statement
The startup's successful podcast and newsletter have led to increased traffic, but non-human traffic is overwhelming their servers, causing frequent downtime that impacts their 3-person engineering team's productivity.

## Setup and Execution

### Prerequisites
- Python 3.x (no additional dependencies required)

### Running the Analysis
```bash
python analyse.py
```

This will generate an `analysis.txt` file containing detailed traffic analysis results.

## Executive Summary

Analysis of server logs from July 1-4, 2025, reveals significant bot traffic contributing to server overload issues. With 432,096 total requests across four days, the startup is experiencing approximately 108,000 daily requests, far exceeding typical capacity for a small team's infrastructure.

## Key Findings

### Bot Traffic Identification
Several IP addresses demonstrate clear bot behavior patterns:
- **Top offenders**: 45.133.1.1 and 45.133.1.2, each generating 5,400 requests (1.2% of total traffic)
- **High-volume IPs**: 16 IP addresses exceeded 1,000 requests over four days, indicating automated scraping rather than human browsing patterns

### Server Performance Impact
- **High error rates** from specific IP ranges (185.220.x.x) correlate with server instability
- **8.8% 404 error rate** and **1.2% internal server errors** suggest bots aggressively crawling non-existent pages
- Resource consumption significantly impacts legitimate user experience

### Geographic Distribution
While traffic appears globally distributed across 14 countries, the concentration of high-volume requests from specific IP ranges indicates coordinated bot networks rather than organic international growth.

## Solutions

### 1. Immediate Rate Limiting
- Implement basic rate limiting (free with most web servers)
- Restrict requests per IP to 100/hour for non-authenticated users
- **Cost**: Free

### 2. Bot Detection Rules
- Block IP addresses exceeding 1,000 daily requests
- Implement simple CAPTCHA challenges for suspicious patterns
- **Estimated monthly cost**: $20-50 for cloud-based solutions

### 3. Infrastructure Optimization
- Leverage free CloudFlare protection tier
- Provides DDoS protection and basic bot filtering
- **Cost**: Free

### 4. Monitoring Setup
- Establish automated log analysis using free tools like fail2ban
- Automatically ban repeat offenders
- **Cost**: Free

## Technical Implementation

### Analysis Methodology
The Python script analyzes:
- Request volume patterns by IP address
- HTTP status code distributions
- Geographic traffic patterns
- Error rate correlations
- Suspicious behavior identification

### Files Included
- `analyse.py` - Main analysis script
- `analysis.txt` - Generated analysis report
- `README.md` - This documentation

## Assumptions

- Current infrastructure uses standard shared hosting without dedicated security measures
- Budget constraints require prioritizing zero-cost solutions
- Minimal disruption to legitimate user experience is essential
- Small team requires automated solutions rather than manual monitoring

## Expected Outcomes

- **40-60% traffic reduction** through bot filtering
- **Elimination of most server downtime incidents** within two weeks of implementation
- **Improved user experience** for legitimate visitors
- **Reduced server load** allowing team to focus on development rather than firefighting

## Cost-Benefit Analysis

The recommended solutions prioritize free options first, with minimal-cost alternatives providing significant impact:
- **Total monthly cost**: $0-50
- **Expected traffic reduction**: 40-60%
- **Downtime reduction**: 80-90%
- **ROI**: Immediate positive impact on user retention and team productivity

---

*This analysis was conducted as part of the IEUK 2025 Engineering Sector Skills Project.*
