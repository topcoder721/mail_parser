import sys
import re
import email
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from advisory import Advisory


def main():
    # Check for test mode
    test_mode = '--test' in sys.argv
    if test_mode:
        sys.argv.remove('--test')
    
    # Read email from file or stdin
    if len(sys.argv) > 1:
        # Read from file specified as command line argument
        email_file = sys.argv[1]
        try:
            with open(email_file, 'r', encoding='utf-8') as f:
                raw_email = f.read()
            print(f"Reading email from file: {email_file}")
        except FileNotFoundError:
            print(f"Error: File '{email_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file '{email_file}': {e}")
            sys.exit(1)
    else:
        # Read from stdin (original behavior)
        raw_email = sys.stdin.read()
    
    # Parse email
    msg = email.message_from_string(raw_email)
    
    # Get headers
    subject = msg.get('Subject', '')
    from_header = msg.get('From', '')
    adv_date = msg.get('Date', '')
    
    # Clean up date
    adv_date = adv_date.replace('\n', '')
    
    # Check if this is a reply or not a security advisory
    if re.match(r'^Subject: (R|r)(E|e):', subject):
        sys.exit(0)
    if 'SECURITY' not in subject:
        sys.exit(0)
    
    # Extract email body
    mail_data = []
    
    def extract_text_parts(msg):
        """Extract text parts from email message"""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type.startswith('text/plain'):
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True)
                    if body:
                        try:
                            if isinstance(body, bytes):
                                body = body.decode(charset, errors='ignore')
                            return body.split('\n')
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
                    return body.split('\n')
                except Exception as e:
                    print(f"Error decoding single part body: {e}")
        return []
    
    mail_data = extract_text_parts(msg)
    
    if not mail_data:
        print("No mail data found")
        sys.exit(1)
    
    # Initialize variables
    short_desc = ""
    advisory = ""
    advisnum = ""
    pkgname = ""
    start_short = False
    line_count = 0
    
    # Process email content
    for line in mail_data:
        advisory += line + "\n"
        
        # Extract advisory number
        fedora_match = re.search(r'^FEDORA-(\S+)', line)
        if fedora_match:
            advisnum = fedora_match.group(1)
        
        # Extract CVE if no FEDORA number found
        if not advisnum:
            cve_match = re.search(r'CVE-(\S+)', line)
            if cve_match:
                advisnum = f"CVE-{cve_match.group(1)}"
        
        # Extract package name
        name_match = re.search(r'^Name\s+:\s*(.*)', line)
        if name_match:
            pkgname = name_match.group(1).replace('\r', '')
        
        # Look for "Update Information" section
        if re.search(r'^Update Information', line):
            start_short = True
            continue
        
        # Process short description
        if start_short:
            if "------------------------------------------------------------------------" in line:
                start_short = False
            elif (line_count < 5 and line.strip() and 
                  line != '\n' and line != '\r' and line != '\r\n'):
                line = re.sub(r'  +', ' ', line)  # Replace multiple spaces with single space
                short_desc += line + " "
                short_desc = re.sub(r'====.+', '', short_desc)  # Remove === lines
                line_count += 1
    
    # Clean up short description
    short_desc = short_desc.strip()
    short_desc = short_desc.replace('\r', '').replace('\n', ' ')
    
    # Format subject line
    fedora_version_match = re.search(r'\[SECURITY\] Fedora (\d+)', subject)
    if fedora_version_match:
        fedora_version = fedora_version_match.group(1)
        subject = f"Fedora {fedora_version}: {pkgname} {advisnum}"
    else:
        # Send failure notification and exit
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, "fedora")
        sys.exit(0)
    
    # Truncate short description if too long
    if len(short_desc) >= 400:
        short_desc = short_desc[:400] + " [More...]"
    
    # In test mode, just show the parsed content
    if test_mode:
        print("\n" + "="*60)
        print("PARSED EMAIL CONTENT (TEST MODE)")
        print("="*60)
        print(f"Original Subject: {msg.get('Subject', '')}")
        print(f"Formatted Subject: {subject}")
        print(f"Date: {adv_date}")
        print(f"Package Name: {pkgname}")
        print(f"Advisory Number: {advisnum}")
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
        advisory_handler.insert_advisory(subject, short_desc, advisory, "fedora", adv_date)
        print(f"Successfully inserted: {subject}")
    except Exception as e:
        print(f"Error inserting advisory: {e}")
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, "fedora")
        sys.exit(1)


if __name__ == "__main__":
    main()