import sys
import re
import email
from email.mime.text import MIMEText
from advisory import Advisory

def main():
    # Check for help
    if '--help' in sys.argv or '-h' in sys.argv:
        print("Usage: python debian_alert3.py [--test] [email_file]")
        print("  --test: Run in test mode (don't insert into database)")
        print("  email_file: Read email from file instead of stdin")
        print("")
        print("Examples:")
        print("  python debian_alert3.py < email.eml")
        print("  python debian_alert3.py --test testfile/debian-failed")
        print("  cat email.eml | python debian_alert3.py --test")
        sys.exit(0)
    
    # Check for test mode
    test_mode = '--test' in sys.argv
    if test_mode:
        sys.argv.remove('--test')
    
    # Initialize variables
    short_desc = ""
    advisory = ""
    file_type = "DEBIAN"
    pkgname = ""
    
    # Read email from file or stdin
    if len(sys.argv) > 1:
        # Read from file specified as command line argument
        email_file = sys.argv[1]
        try:
            with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
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
    
    # Check if this is a reply or doesn't contain SECURITY
    if re.match(r'^(R|r)(E|e):', subject):
        print(f"Reply email, skipping: {subject}")
        sys.exit(0)
    
    if 'SECURITY' not in subject:
        print(f"Not a security advisory: {subject}")
        sys.exit(0)

    patterns = [
        r'\[SECURITY\] \[DSA (\d+)-(\d+)\] (.*)',
        r'\[SECURITY\] \[DSA-(\d+)-(\d+)\] (.*)',
        r'\[SECURITY\] \[DSA (\d+)-(\d+)\]\s+New (.*)',
        r'\[SECURITY\] \[DSA-(\d+)-(\d+)\]\s+New (.*)',
    ]
    
    matched = False
    for pattern in patterns:
        match = re.search(pattern, subject, re.IGNORECASE)
        if match:
            dsa_num = match.group(1)
            dsa_rev = match.group(2)
            package_info = match.group(3).strip()
            subject = f"Debian: DSA-{dsa_num}-{dsa_rev}: {package_info}"
            matched = True
            break
    
    if not matched:
        error_msg = "Failed to parse subject - no matching DSA pattern found"
        print(f"Failed to parse subject: {subject}")
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, file_type, error_msg)
        sys.exit(0)
    
    # Extract email body - handle different content types
    def extract_text_parts(msg):
        """Extract text parts from email message"""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type and content_type.startswith('text/plain'):
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True)
                    if body:
                        try:
                            if isinstance(body, bytes):
                                body = body.decode(charset, errors='ignore')
                            return body
                        except Exception as e:
                            print(f"Error decoding body: {e}")
                            continue
        else:
            # Single part message
            body = msg.get_payload(decode=True)
            if body:
                charset = msg.get_content_charset() or 'utf-8'
                try:
                    if isinstance(body, bytes):
                        body = body.decode(charset, errors='ignore')
                    return body
                except Exception as e:
                    print(f"Error decoding single part body: {e}")
        
        # Fallback to raw buffer if no MIME parts found
        return buf
    
    mail_content = extract_text_parts(msg)
    
    if not mail_content:
        print("No mail content found")
        sys.exit(1)
    
    mail_data = mail_content.split('\n')
    
    # Process email body
    pkgstart = 0
    advisend = False
    nlines = 0
    short_desc_lines = []
    nomime = False
    
    for line in mail_data:
        line = line.rstrip('\n\r')
        
        # Handle emails with no MIME boundaries (look for Hash: line)
        if not nomime and 'Hash:' not in line:
            continue
        elif 'Hash:' in line:
            nomime = True
            continue
        
        # End of advisory - don't need PGP signature or mailing list stuff
        if line.startswith('-----BEGIN PGP SIGNATURE') and nlines == 5 and pkgstart == 2:
            advisend = True
        
        if advisend:
            break
        
        # Collect full advisory text
        advisory += line + "\n"
        
        # Check for "Package" or "Vulnerability" line
        if (re.match(r'^Vulnerability\s+:', line) or 
            re.match(r'^Package(s)?\s+:', line) or 
            re.match(r'^Package(s)?\s+:', line)):
            pkgstart = 1
        
        # Blocks of text after "Package" and before the first newline
        if line.strip() and pkgstart == 1:
            continue
        
        # First newline after Package section
        if not line.strip() and pkgstart == 1:
            pkgstart = 2
        
        # Collect short description (5 lines after Package section)
        if pkgstart == 2 and nlines < 5:
            if line.strip():  # Only add non-empty lines
                short_desc_lines.append(line.strip())
                nlines += 1
    
    # Join short description lines
    short_desc = ' '.join(short_desc_lines)
    
    # Check if we found the package section
    if pkgstart == 0:
        error_msg = "Failed to find Package section in email body"
        print("Failed to find Package section")
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, file_type, error_msg)
        sys.exit(0)
    
    # Clean up short description and subject
    short_desc = re.sub(r'^ +', '', short_desc)
    short_desc = re.sub(r' +', ' ', short_desc)
    short_desc = re.sub(r'\n', '', short_desc)
    short_desc = short_desc.strip()
    
    subject = re.sub(r'\n', '', subject)
    subject = re.sub(r'(moderate|important|security|update)', '', subject, flags=re.IGNORECASE)
    subject = subject.strip()
    
    # Ensure we have content
    if not short_desc:
        print("Warning: No short description found")
        short_desc = "Security update"
    
    if not advisory.strip():
        error_msg = "No advisory content found in email body"
        print("Warning: No advisory content found")
        advisory_handler = Advisory()
        advisory_handler.send_failed(f"No advisory content: {subject}", file_type, error_msg)
        sys.exit(1)
    
    print(f"subject: |{subject}|")
    print(f"date: |{adv_date}|")
    print(f"shortdesc: |{short_desc}|")
    
    # In test mode, show parsed content without database insertion
    if test_mode:
        print("\n" + "="*60)
        print("PARSED EMAIL CONTENT (TEST MODE)")
        print("="*60)
        print(f"Original Subject: {msg.get('Subject', '')}")
        print(f"Formatted Title: {subject}")
        print(f"sent from: {from_addr}")
        print(f"Date: {adv_date}")
        print(f"Short Description ({len(short_desc)} chars): {short_desc}")
        print("\nFull Advisory Content:")
        print("-" * 40)
        print(advisory[:500] + "..." if len(advisory) > 500 else advisory)
        print("="*60)
        print("Test mode - no database insertion attempted")
        return
    
    # Insert advisory into database (production mode)
    try:
        advisory_handler = Advisory()
        advisory_handler.insert_advisory(subject, short_desc, advisory, "debian", adv_date)
        print(f"Successfully inserted: {subject}")
    except Exception as e:
        error_msg = f"Database insertion error: {str(e)}"
        print(f"Error inserting advisory: {e}")
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, "debian", error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()
