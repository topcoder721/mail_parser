
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
    # Check for help
    if '--help' in sys.argv or '-h' in sys.argv:
        print("Usage: python mageia_alert1.py [--test] [email_file]")
        print("  --test: Run in test mode (don't insert into database)")
        print("  email_file: Read email from file instead of stdin")
        print("")
        print("Examples:")
        print("  python mageia_alert1.py < email.eml")
        print("  python mageia_alert1.py --test testfile/mageia-works.eml")
        print("  cat email.eml | python mageia_alert1.py --test")
        sys.exit(0)
    
    # Check for test mode
    test_mode = '--test' in sys.argv
    if test_mode:
        sys.argv.remove('--test')
    
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
    
    # Read email from file or stdin
    if len(sys.argv) > 1:
        # Read from file specified as command line argument
        email_file = sys.argv[1]
        try:
            with open(email_file, 'r', encoding='utf-8') as f:
                buf = f.read()
            print(f"Reading email from file: {email_file}")
        except FileNotFoundError:
            print(f"Error: File '{email_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file '{email_file}': {e}")
            sys.exit(1)
    else:
        # Read from stdin (original behavior)
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
    
    # Check if this is a Mageia advisory (MGASA- or MGAA-)
    if 'MGASA-' not in subject and 'MGAA-' not in subject:
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
        # MGAA-2025-0082: Updated nvidia-current packages fix bugs
        r'MGAA-(\d+)-(\d+):\s*Updated\s+(.*?)\s+packages?\s+fix\s+bugs?',
        # MGASA-2019-0151 - Updated package packages fix security vulnerabilities
        r'MGASA-(\d+)-(\d+)\s*-\s*Updated\s+(.*?)\s+packages?\s+fix\s+security\s+vulnerabilities?',
        # MGASA-2019-0151 - Updated package package fix security vulnerabilities
        r'MGASA-(\d+)-(\d+)\s*-\s*Updated\s+(.*?)\s+package\s+fix\s+security\s+vulnerabilities?',
        # MGASA-2019-0151 - Virtualbox 6.0.6 fixes security vulnerabilities  
        r'MGASA-(\d+)-(\d+)\s*-\s*(.*?)\s+(.*?)\s+fixes?\s+security\s+vulnerabilities?',
        # Generic fallback - just extract the advisory number
        r'MGASA-(\d+)-(\d+)',
        r'MGAA-(\d+)-(\d+)',
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
    in_headers = True
    found_body_start = False
    collecting_short_desc = False
    short_desc_lines = []
    
    for line in mail_data:
        line = line.rstrip('\n\r')
        
        # Skip headers until we find the first empty line
        if in_headers:
            if line == '':
                in_headers = False
                found_body_start = True
            continue
        
        # After headers, look for the advisory content
        if found_body_start:
            # Look for the advisory line (first non-empty line that starts with MGA)
            if line.strip() and inadvis is False:
                collecting_short_desc = True
                inadvis = True
            
            # If we're collecting short description and haven't hit "Publication date:" yet
            if collecting_short_desc and not line.startswith('Publication date:'):
                if line.strip():  # Only add non-empty lines
                    short_desc_lines.append(line.strip())
            elif line.startswith('Publication date:'):
                # Stop collecting short description
                collecting_short_desc = False
            
            # Collect full advisory text once we've found the start
            if inadvis:
                advisory += line + "\n"
    
    # Join short description lines
    short_desc = ' '.join(short_desc_lines)
    
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
    
    # In test mode, show parsed content without database insertion
    if test_mode:
        print("\n" + "="*60)
        print("PARSED EMAIL CONTENT (TEST MODE)")
        print("="*60)
        print(f"Original Subject: {subject}")
        print(f"Formatted Title: {sub}")
        print(f"sent from: {from_addr}")
        print(f"Package Name: {pkgname}")
        print(f"Date: {adv_date}")
        print(f"Short Description ({len(short_desc)} chars): {short_desc}")
        print("\nFull Advisory Content:")
        print("-" * 40)
        print(advisory[:500] + "..." if len(advisory) > 500 else advisory)
        print("="*60)
        print("Test mode - no database insertion attempted")
        return
    
    # Insert advisory into database (production mode)
    insert_advisory(sub, short_desc, advisory, "mageia", adv_date)

if __name__ == "__main__":
    main()