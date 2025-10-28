#!/usr/bin/env python3

import sys
import re
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from advisory import Advisory


def extract_introtext_from_content(content):
    """
    Extract introtext from email content.
    Extracts ALL text between "Affected Products" section and "Description" section.
    
    Type 1: Has "Affected Products:" with bullet points (*), introtext before "## Description:"
    Type 2: Has "Affected Products:" with individual lines, ends with underscores, introtext before "Description:"
    """
    lines = content.split('\n')
    
    # Find the Affected Products section to determine the type
    affected_products_idx = -1
    affected_products_type = None
    
    for i, line in enumerate(lines):
        if line.strip() == "Affected Products:":
            affected_products_idx = i
            # Check the format after "Affected Products:"
            # Look ahead to see if we have bullet points or individual lines
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1  # Skip empty lines
            
            if j < len(lines):
                next_content_line = lines[j].strip()
                if next_content_line.startswith('*'):
                    affected_products_type = 1  # Type 1: bullet points
                else:
                    affected_products_type = 2  # Type 2: individual lines
            break
    
    if affected_products_idx == -1:
        # No "Affected Products:" found, fall back to original pattern matching
        return extract_introtext_fallback(lines)
    
    # Find the end of the Affected Products section
    affected_products_end = -1
    
    if affected_products_type == 1:
        # Type 1: Look for the end of bullet points
        for i in range(affected_products_idx + 1, len(lines)):
            line = lines[i].strip()
            if line and not line.startswith('*') and not line.startswith('  *'):
                # Found end of bullet points
                affected_products_end = i
                break
    else:
        # Type 2: Look for the line with underscores (this marks the END of affected products)
        for i in range(affected_products_idx + 1, len(lines)):
            line = lines[i].strip()
            if line.startswith('_'):
                affected_products_end = i + 1  # Start after the underscore line
                break
    
    if affected_products_end == -1:
        return extract_introtext_fallback(lines)
    
    # Now find the Description marker
    description_marker = "## Description:" if affected_products_type == 1 else "Description:"
    description_idx = -1
    
    for i in range(affected_products_end, len(lines)):
        line = lines[i].strip()
        if line == description_marker:
            description_idx = i
            break
    
    if description_idx == -1:
        return extract_introtext_fallback(lines)
    
    # Extract ALL text between affected_products_end and description_idx
    introtext_lines = []
    for i in range(affected_products_end, description_idx):
        line = lines[i].strip()
        if line:  # Only add non-empty lines
            introtext_lines.append(line)
    
    if introtext_lines:
        # Join all lines with spaces
        introtext = ' '.join(introtext_lines)
        return introtext.strip()
    
    # Fallback to original pattern matching
    return extract_introtext_fallback(lines)


def extract_introtext_fallback(lines):
    """
    Fallback method for extracting introtext using original pattern matching.
    """
    # Pattern 1: Look for "An update that solves/fixes..." pattern anywhere
    for i, line in enumerate(lines):
        line = line.strip()
        if re.match(r'^An update that (solves|fixes|contains)', line, re.IGNORECASE):
            # Found the introtext line, collect it and potentially the next line(s)
            introtext = line
            
            # Look ahead for continuation lines
            j = i + 1
            while j < len(lines):
                next_line = lines[j].strip()
                if not next_line:
                    j += 1
                    continue
                if next_line.startswith('#') or next_line.startswith('##'):
                    break
                
                # Check if this looks like a continuation
                if (next_line.startswith('is now available') or 
                    next_line.startswith('can now be') or
                    next_line.startswith('are now available') or
                    next_line.startswith('installed')):
                    introtext += ' ' + next_line
                    break
                elif not introtext.endswith('.') and len(next_line) > 10:
                    # If the current line doesn't end with a period and next line is substantial
                    introtext += ' ' + next_line
                    j += 1
                else:
                    break
            
            return introtext.strip()
    
    # Pattern 2: Look for other common introtext patterns
    for line in lines:
        line = line.strip()
        # Match patterns like "Security update for..." or "Update for..."
        if re.match(r'^(Security )?[Uu]pdate (for|to) .+ (is|are) now available', line, re.IGNORECASE):
            return line.strip()
        # Match patterns like "This update fixes..."
        if re.match(r'^This update (fixes|addresses|resolves)', line, re.IGNORECASE):
            return line.strip()
    
    return ""


def update_missing_introtext(test_mode=False, limit=None, specific_ids=None):
    """
    Update records that have empty or null introtext fields.
    """
    advisory_handler = Advisory()
    databases = ["lsv7", "lsv7j5beta"]
    
    for dbname in databases:
        print(f"\nProcessing database: {dbname}")
        
        connection = advisory_handler.db_connect(dbname)
        if not connection:
            print(f"Failed to connect to database {dbname}")
            continue
        
        cursor = connection.cursor()
        
        # Find records with empty introtext but non-empty fulltext
        if specific_ids:
            # Query for multiple specific IDs
            placeholders = ','.join(['%s'] * len(specific_ids))
            query = f"""
            SELECT id, title, introtext, `fulltext`, created
            FROM xu5gc_content 
            WHERE id IN ({placeholders})
            AND catid = 202 
            AND (introtext IS NULL OR introtext = '' OR TRIM(introtext) = '')
            AND `fulltext` IS NOT NULL 
            AND `fulltext` != ''
            ORDER BY id
            """
            cursor.execute(query, specific_ids)
        else:
            # Query for records with missing introtext
            query = """
            SELECT id, title, introtext, `fulltext`, created
            FROM xu5gc_content 
            WHERE catid = 202 
            AND (introtext IS NULL OR introtext = '' OR TRIM(introtext) = '')
            AND `fulltext` IS NOT NULL 
            AND `fulltext` != ''
            ORDER BY created DESC
            """
            
            if limit:
                query += f" LIMIT {limit}"
            
            cursor.execute(query)
        
        records = cursor.fetchall()
        
        if specific_ids:
            if records:
                found_ids = [str(record[0]) for record in records]
                missing_ids = [str(id) for id in specific_ids if str(id) not in found_ids]
                print(f"Found {len(records)} records with IDs: {', '.join(found_ids)}")
                if missing_ids:
                    print(f"Missing or invalid IDs: {', '.join(missing_ids)}")
            else:
                print(f"No records found with IDs {', '.join(map(str, specific_ids))} or records don't meet criteria")
                cursor.close()
                advisory_handler.db_disconnect(connection)
                continue
        else:
            print(f"Found {len(records)} records with missing introtext")
        
        updated_count = 0
        
        for record in records:
            record_id, title, current_introtext, fulltext, created = record
            
            # Remove HTML tags for easier parsing
            content = re.sub(r'<[^>]+>', '', fulltext)
            content = re.sub(r'&lt;', '<', content)
            content = re.sub(r'&gt;', '>', content)
            content = re.sub(r'&amp;', '&', content)
            
            # Extract introtext from fulltext using the same function
            new_introtext = extract_introtext_from_content(content)
            
            if new_introtext:
                # Truncate if too long
                if len(new_introtext) >= 400:
                    new_introtext = new_introtext[:400] + " [More...]"
                
                print(f"\nID: {record_id}")
                print(f"Title: {title}")
                print(f"Created: {created}")
                print(f"Current introtext: '{current_introtext}'")
                print(f"New introtext: '{new_introtext}'")
                
                if not test_mode:
                    # Update the record
                    update_query = "UPDATE xu5gc_content SET introtext = %s WHERE id = %s"
                    cursor.execute(update_query, (new_introtext, record_id))
                    updated_count += 1
                    print("✓ Updated")
                else:
                    print("✓ Would update (test mode)")
                    updated_count += 1
            else:
                print(f"\nID: {record_id} - No introtext pattern found in: {title}")
        
        cursor.close()
        advisory_handler.db_disconnect(connection)
        
        print(f"\nDatabase {dbname}: {'Would update' if test_mode else 'Updated'} {updated_count} records")


def main():
    # Check for update mode
    update_mode = '--update-missing' in sys.argv
    if update_mode:
        sys.argv.remove('--update-missing')
        
        # Check for test mode
        test_mode = '--test' in sys.argv
        if test_mode:
            sys.argv.remove('--test')
        
        # Check for limit and ids parameters
        limit = None
        specific_ids = None
        i = 0
        while i < len(sys.argv[1:]):
            arg = sys.argv[i + 1]
            if arg.startswith('--limit='):
                limit = int(arg.split('=')[1])
                sys.argv.remove(arg)
                break
            elif arg == '--limit':
                if i + 1 < len(sys.argv[1:]):
                    limit = int(sys.argv[i + 2])
                    sys.argv.remove(arg)
                    sys.argv.remove(str(limit))
                    break
                else:
                    print("Error: --limit requires a value")
                    sys.exit(1)
            elif arg.startswith('--ids='):
                ids_str = arg.split('=')[1]
                specific_ids = [int(x.strip()) for x in ids_str.split(',')]
                sys.argv.remove(arg)
                break
            elif arg == '--ids':
                if i + 1 < len(sys.argv[1:]):
                    ids_str = sys.argv[i + 2]
                    specific_ids = [int(x.strip()) for x in ids_str.split(',')]
                    sys.argv.remove(arg)
                    sys.argv.remove(ids_str)
                    break
                else:
                    print("Error: --ids requires a comma-separated list of values")
                    sys.exit(1)
            elif arg in ['--help', '-h']:
                print("Usage: python opensuse_alert.py --update-missing [--test] [--limit N] [--ids N,N,N]")
                print("  --update-missing: Update existing records with missing introtext")
                print("  --test: Run in test mode (don't actually update)")
                print("  --limit N or --limit=N: Limit to N records per database")
                print("  --ids N,N,N or --ids=N,N,N: Update multiple specific record IDs (comma-separated)")
                sys.exit(0)
            i += 1
        
        if test_mode:
            print("Running in TEST MODE - no actual updates will be made")
        
        update_missing_introtext(test_mode, limit, specific_ids)
        return
    
    # Check for help
    if '--help' in sys.argv or '-h' in sys.argv:
        print("Usage: python opensuse_alert.py [--test] [email_file]")
        print("  --test: Run in test mode (don't insert into database)")
        print("  email_file: Read email from file instead of stdin")
        print("")
        print("Database update mode:")
        print("  python opensuse_alert.py --update-missing [--test] [--limit=N] [--ids=N,N,N]")
        print("  --update-missing: Update existing records with missing introtext")
        print("  --test: Run in test mode (don't actually update)")
        print("  --limit=N: Limit to N records per database")
        print("  --ids=N,N,N: Update multiple specific record IDs (comma-separated)")
        sys.exit(0)
    
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
    adv_date = adv_date.replace('\n', '').replace('\r', '')
    
    # Extract email body
    def extract_text_parts(msg):
        """Extract text parts from email message"""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if (content_type.startswith('text/plain') and 
                    not part.get_filename()):  # Skip attachments
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
        return ""
    
    mail_content = extract_text_parts(msg)
    
    if not mail_content:
        print("No mail content found")
        sys.exit(1)
    
    # Initialize variables
    short_desc = ""
    advisory = mail_content
    vendor = ""
    
    # Clean up subject and extract vendor info
    subject = re.sub(r'\. +', '. ', subject)
    subject = re.sub(r'\s+', ' ', subject)
    subject = re.sub(r'\n', ' ', subject)
    subject = re.sub(r'\t', ' ', subject)
    subject = re.sub(r'^ +', '', subject)
    subject = re.sub(r' +$', '', subject)
    subject = re.sub(r'the linux kernel', 'kernel', subject, flags=re.IGNORECASE)
    subject = subject.strip()
    
    # Parse different subject formats
    if re.search(r'\[security-announce\] openSUSE-SU-(\d+):(\d+)-(\d+): (.*)$', subject):
        match = re.search(r'\[security-announce\] openSUSE-SU-(\d+):(\d+)-(\d+): (.*)$', subject)
        subject = f"openSUSE: {match.group(1)}:{match.group(2)}-{match.group(3)}: {match.group(4)}"
        vendor = "opensuse"
    elif re.search(r'\[opensuse-security-announce\]\s+openSUSE-SU-(\d+):(\d+)-(\d+): (\w+): Security update for (.*)', subject):
        match = re.search(r'\[opensuse-security-announce\]\s+openSUSE-SU-(\d+):(\d+)-(\d+): (\w+): Security update for (.*)', subject)
        subject = f"openSUSE: {match.group(1)}:{match.group(2)}-{match.group(3)} {match.group(4)}: {match.group(5)}"
        vendor = "opensuse"
    elif re.search(r'SUSE-SU-(\d+):(\d+)-(\d+): (\w+): Security update for (.*)', subject):
        match = re.search(r'SUSE-SU-(\d+):(\d+)-(\d+): (\w+): Security update for (.*)', subject)
        subject = f"openSUSE: {match.group(1)}:{match.group(2)}-{match.group(3)} {match.group(4)}: {match.group(5)}"
        vendor = "opensuse"
    elif re.search(r'SUSE-SU-(\d+):(\d+)-(\d+): (\w+): (.*) on GA media', subject):
        match = re.search(r'SUSE-SU-(\d+):(\d+)-(\d+): (\w+): (.*) on GA media', subject)
        subject = f"openSUSE: {match.group(1)}:{match.group(2)}-{match.group(3)} {match.group(4)}: {match.group(5)}"
        vendor = "opensuse"
    elif re.search(r'openSUSE-SU-(\d+):(\d+)-(\d+): Security update for (.*)', subject):
        match = re.search(r'openSUSE-SU-(\d+):(\d+)-(\d+): Security update for (.*)', subject)
        subject = f"openSUSE: {match.group(1)}:{match.group(2)}-{match.group(3)}: {match.group(4)}"
        vendor = "opensuse"
    elif re.search(r'openSUSE-SU-(\d+):(\d+)-(\d+): (\w+): Recommended update for (.*)', subject):
        match = re.search(r'openSUSE-SU-(\d+):(\d+)-(\d+): (\w+): Recommended update for (.*)', subject)
        subject = f"openSUSE: {match.group(1)}:{match.group(2)}-{match.group(3)}: {match.group(4)}: {match.group(5)}"
        vendor = "opensuse"
    elif re.search(r'openSUSE-SU-4(\d+)-(\d+): (\w+): Security update for (.*)', subject):
        match = re.search(r'openSUSE-SU-4(\d+)-(\d+): (\w+): Security update for (.*)', subject)
        subject = f"openSUSE: 4{match.group(1)}-{match.group(2)} {match.group(3)}: {match.group(4)}"
        vendor = "opensuse"
    else:
        # Send failure notification and exit
        error_msg = "Subject does not match any known OpenSUSE security advisory pattern"
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, "opensuse", error_msg)
        print("send failed due to subject or vendor mismatch")
        sys.exit(0)
    
    # Clean up subject further
    subject = re.sub(r'Security update for', '', subject)
    subject = re.sub(r' \(Live .*', '', subject)
    subject = re.sub(r'update to', '', subject)
    subject = re.sub(r'update for', '', subject)
    subject = re.sub(r' to .*', '', subject)
    subject = re.sub(r' +', ' ', subject)
    subject = re.sub(r'important: (.*):.*', r'important: \1', subject)
    subject = re.sub(r'critical: (.*):.*', r'critical: \1', subject)
    subject = re.sub(r'moderate: (.*):.*', r'critical: \1', subject)
    subject = re.sub(r'moderate', '', subject, flags=re.IGNORECASE)
    subject = re.sub(r'important', '', subject, flags=re.IGNORECASE)
    subject = re.sub(r'security', '', subject, flags=re.IGNORECASE)
    subject = re.sub(r'update', '', subject, flags=re.IGNORECASE)
    subject = subject.strip()
    
    # Extract introtext using the new function
    short_desc = extract_introtext_from_content(mail_content)
    
    # If no introtext found, try to extract from first few lines after headers
    if not short_desc:
        lines = mail_content.split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            # Skip empty lines and headers
            if not line or line.startswith('#') or ':' in line[:50]:
                continue
            # Look for descriptive text
            if len(line) > 20 and not line.startswith('Announcement ID'):
                short_desc = line
                break
    
    # Clean up short description
    if short_desc:
        short_desc = re.sub(r'\. +', '. ', short_desc)
        short_desc = re.sub(r'\s+', ' ', short_desc)
        short_desc = re.sub(r'\n', ' ', short_desc)
        short_desc = re.sub(r'^\s+', '', short_desc)
        short_desc = re.sub(r'\s+$', '', short_desc)
        short_desc = short_desc.strip()
        
        # Truncate if too long
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
        print(f"Vendor: {vendor}")
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
        advisory_handler.insert_advisory(subject, short_desc, advisory, vendor, adv_date)
        print(f"Successfully inserted: {subject}")
    except Exception as e:
        error_msg = f"Database insertion error: {str(e)}"
        print(f"Error inserting advisory: {e}")
        advisory_handler = Advisory()
        advisory_handler.send_failed(subject, vendor, error_msg)
        sys.exit(1)


if __name__ == "__main__":
    main()
