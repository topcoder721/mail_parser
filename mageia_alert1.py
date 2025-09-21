#!/usr/bin/env python3

"""
Parses Mageia Security Alerts for automatic
insertion into linuxsecurity.com

Converted from Perl to Python
Dave Wreski <dwreski@guardiandigital.com>
08/31/2018

Issues fixed in Python conversion:
- Better handling of long subject lines with multiple packages
- Improved regex patterns for subject parsing
- More robust email parsing
- Better error handling and logging
- Fixed issue where MGAA- (bug fix) advisories were not being processed
  (they should be ignored as they're not security advisories)
"""

import sys
import re
import email
from email.mime.text import MIMEText
from advisory import Advisory

def send_failed(subject, file_type):
    """Send failure notification"""
    try:
        advisory = Advisory()
        advisory.send_failed(subject, file_type)
    except Exception as e:
        print(f"Error sending failure notification: {e}")

def insert_advisory(title, short_desc, advisory_text, os_name, adv_date):
    """Insert advisory into database"""
    try:
        advisory = Advisory()
        advisory.insert_advisory(title, short_desc, advisory_text, os_name, adv_date)
    except Exception as e:
        print(f"Error inserting advisory: {e}")
        # Still send failure notification even if database insert fails
        send_failed(f"Database insert failed for: {title}", os_name)

def main():
    # Initialize variables
    short_desc = ""
    advisory = ""
    advisnum = ""
    in_body = False
    in_summary = False
    in_details = False
    oneline = False
    prev_line = False
    nlines = 0
    vulndesc = ""
    file_type = "MAGEIA"
    start_body = False
    start_short = False
    pkgname = ""
    
    # Read email from stdin
    try:
        buf = sys.stdin.read()
        if not buf.strip():
            print("No input received")
            sys.exit(1)
    except Exception as e:
        print(f"Error reading input: {e}")
        sys.exit(1)
    
    mail_data = buf.split('\n')
    
    # Parse email
    try:
        msg = email.message_from_string(buf)
        subject = msg.get('Subject', '').strip()
        from_addr = msg.get('From', '')
        adv_date = msg.get('Date', '').strip()
    except Exception as e:
        print(f"Error parsing email: {e}")
        sys.exit(1)
    
    # Remove newlines from date
    adv_date = adv_date.replace('\n', '').replace('\r', '')
    
    # Check if this is a security advisory (MGASA-) vs bug fix (MGAA-)
    if 'MGASA-' not in subject:
        if 'MGAA-' in subject:
            print(f"Bug fix advisory (MGAA-), not security advisory: {subject}")
        else:
            print(f"Not a Mageia advisory: {subject}")
        sys.exit(0)
    
    # Clean subject - remove various line break characters
    subject = re.sub(r'[\r\n\x0b\x0c]', '', subject)
    
    # Initialize counters and flags
    linecount = 0
    inadvis = False
    sub = ''
    insub = False
    
    # Parse subject line to extract package name and create title
    # Order matters - more specific patterns first
    patterns = [
        # MGASA-2023-0357: Updated libssh packages fix security vulnerabilities
        r'MGASA-(\d+)-(\d+):\s*Updated\s+(.*?)\s+packages?\s+fix\s+security\s+vulnerabilities?',
        # MGASA-2023-0356: Updated proftpd packages fix a security vulnerability  
        r'MGASA-(\d+)-(\d+):\s*Updated\s+(.*?)\s+packages?\s+fix\s+a\s+security\s+vulnerability',
        # MGASA-2024-0220: Updated aom packages fix security vulnerability
        r'MGASA-(\d+)-(\d+):\s*Updated\s+(.*?)\s+packages?\s+fix\s+security\s+vulnerability',
        # MGASA-2023-0355: New chromium-browser-stable 120.0.6099.129 fixes bugs and vulnerabilities
        r'MGASA-(\d+)-(\d+):\s*New\s+(.*?)\s+(.*?)\s+fixes\s+bugs\s+and',
        # MGASA-2019-0151 - Updated package packages fix security vulnerabilities
        r'MGASA-(\d+)-(\d+)\s*-\s*Updated\s+(.*?)\s+packages?\s+fix\s+security\s+vulnerabilities?',
        # MGASA-2019-0151 - Updated package package fix security vulnerabilities
        r'MGASA-(\d+)-(\d+)\s*-\s*Updated\s+(.*?)\s+package\s+fix\s+security\s+vulnerabilities?',
        # MGASA-2019-0151 - Virtualbox 6.0.6 fixes security vulnerabilities  
        r'MGASA-(\d+)-(\d+)\s*-\s*(.*?)\s+(.*?)\s+fixes?\s+security\s+vulnerabilities?',
        # Generic fallback - just extract the advisory number
        r'MGASA-(\d+)-(\d+)',
    ]
    
    for i, pattern in enumerate(patterns):
        match = re.search(pattern, subject, re.IGNORECASE)
        if match:
            year = match.group(1)
            num = match.group(2)
            
            if len(match.groups()) >= 3:
                packages = match.group(3).strip()
                
                # Handle comma-separated packages - take only the first one
                # Also handle & and other separators
                separators = [',', '&', ' and ', ' & ']
                pkgname = packages
                
                for sep in separators:
                    if sep in packages:
                        pkg_list = [pkg.strip() for pkg in packages.split(sep)]
                        pkgname = pkg_list[0] if pkg_list else packages
                        break
                
                # Clean up package name
                pkgname = re.sub(r'[&\s]+', ' ', pkgname).strip()
                
            else:
                # Fallback - try to extract package name from subject
                pkg_match = re.search(r'Updated\s+([\w-]+)', subject, re.IGNORECASE)
                if pkg_match:
                    pkgname = pkg_match.group(1)
                else:
                    pkgname = "unknown"
            
            sub = f"Mageia {year}-{num}: {pkgname}"
            insub = True
            print(f"Matched pattern {i+1}: {pattern}")
            break
    
    # Clean up subject
    sub = sub.replace('Security Advisory Updates', '')
    
    print(f"subject: |{subject}|")
    print(f"sub: |{sub}| file: {file_type}")
    print(f"pkgname: |{pkgname}|")
    
    # If subject parsing failed, send failure notification and exit
    if not insub:
        print(f"Failed to parse subject: {subject}")
        send_failed(subject, file_type)
        sys.exit(0)
    
    # Process email body
    for line in mail_data:
        line = line.rstrip('\n\r')
        
        # Find start of body (empty line)
        if line == '' and not inadvis:
            inadvis = True
            continue
        
        # Look for Description section
        if line.startswith('Description:'):
            start_short = True
            continue
        
        # Collect short description (first 5 lines after Description:)
        if linecount < 5 and start_short:
            if line.strip():  # Skip empty lines
                short_desc += line + " "
                linecount += 1
        
        # Look for advisory number to start collecting full advisory
        if re.match(r'^MGASA-', line):
            inadvis = True
        
        # Collect full advisory text
        if inadvis:
            advisory += line + "\n"
    
    # Clean up short description
    short_desc = short_desc.strip()
    
    # Ensure we have content
    if not short_desc:
        print("Warning: No short description found")
        short_desc = "Security update"
    
    if not advisory.strip():
        print("Warning: No advisory content found")
        send_failed(f"No advisory content: {subject}", file_type)
        sys.exit(1)
    
    print(f"date: |{adv_date}|")
    print(f"shortdesc: |{short_desc}|")
    print(f"sub: |{sub}|")
    
    # Insert advisory into database
    insert_advisory(sub, short_desc, advisory, "mageia", adv_date)

if __name__ == "__main__":
    main()