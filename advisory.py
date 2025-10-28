#!/usr/bin/env python3

import mysql.connector
from mysql.connector import Error
import json
import re
import string
import random
from datetime import datetime
import time
import subprocess
import sys
from email.utils import parsedate_to_datetime


class Advisory:
    def __init__(self):
        self.db_config = {
            # 'host': 'havoc.guardiandigital.com',
            'host': 'localhost',
            # 'user': 'lsjoomla',
            'user': 'root',
            # 'password': '64V%^pEo05aT',
            'password': 'gscnexus',
            'port':3307,
            'charset': 'utf8mb4',
            'use_unicode': True,
            'autocommit': True
        }
        
        self.category_map = {
            'caldera': 85,
            'conectiva': 86,
            'debian': 87,
            'engarde': 88,
            'fedora': 89,
            'freebsd': 90,
            'gentoo': 91,
            'immunix': 92,
            'mandrake': 93,
            'netbsd': 94,
            'openbsd': 95,
            'openwall': 96,
            'pardus': 174,
            'redhat': 98,
            'slackware': 99,
            'suse': 100,
            'trustix': 97,
            'turbolinux': 101,
            'ubuntu': 172,
            'yellowdog': 122,
            'archlinux': 198,
            'scientific': 200,
            'oracle': 217,
            'mageia': 203,
            'opensuse': 202,
            'deblts': 197,
            'centos': 199,
            'rockylinux': 199,  # Added rockylinux
            'other': 97,
        }

    def db_connect(self, database):
        """Connect to MySQL database"""
        try:
            config = self.db_config.copy()
            config['database'] = database
            connection = mysql.connector.connect(**config)
            return connection
        except Error as e:
            print(f"Error connecting to MySQL: {e}")
            return None

    def db_disconnect(self, connection):
        """Disconnect from MySQL database"""
        if connection and connection.is_connected():
            connection.close()

    def get_catid(self, os_name):
        """Get category ID for operating system"""
        return self.category_map.get(os_name.lower(), self.category_map['other'])

    def generate_random_id(self, length=12):
        """Generate random ID for title alias"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    def clean_title_alias(self, title):
        """Clean title for use as alias"""
        alias = title.lower()
        
        # Apply various cleaning rules
        alias = re.sub(r'security and bug fix (update)?', '', alias)
        alias = re.sub(r'-security-advisory-update-', '-', alias)
        alias = re.sub(r'[\[\]]', '', alias)
        alias = re.sub(r'x86_64', 'x86-64', alias)
        alias = re.sub(r'<93>', '"', alias)
        alias = re.sub(r'<94>', '"', alias)
        alias = re.sub(r'<92>', "'", alias)
        alias = re.sub(r'<97>', '--', alias)
        alias = re.sub(r'"', '', alias)
        alias = re.sub(r'[^\x20-\x7E\r\n]', '', alias)  # Remove non-printable chars
        alias = alias.rstrip()
        alias = re.sub(r',$', '', alias)
        alias = re.sub(r'-$', '', alias)
        alias = re.sub(r'\.+', '-', alias)
        alias = re.sub(r':+', '-', alias)
        alias = re.sub(r',+', '-', alias)
        alias = re.sub(r"'", '', alias)
        alias = re.sub(r'/', '-', alias)
        alias = re.sub(r' +', '-', alias)
        alias = re.sub(r'_', '-', alias)
        alias = re.sub(r'[^\x00-\x7F]', '', alias)  # Remove non-ASCII
        alias = re.sub(r'-+', '-', alias)
        alias = re.sub(r'[ :!@#$%^&*()+=./]', '-', alias)
        alias = re.sub(r'--', '-', alias)
        alias = re.sub(r'-$', '', alias)
        
        # Add random ID
        random_id = self.generate_random_id()
        alias = f"{alias}-{random_id.lower()}"
        
        return alias.strip()

    def get_distro_images(self, os_name):
        """Get distribution-specific images"""
        distro_images = {
            'archlinux': {
                'float_fulltext': 'images/distros/ls_advisories_archlinux.jpg',
                'distimage': 'images/distros-large/archlinux-large.png'
            },
            'centos': {
                'float_fulltext': 'images/distros/ls_advisories_centos.jpg',
                'distimage': 'images/distros-large/centos-large.png'
            },
            'debian': {
                'float_fulltext': 'images/distros/ls_advisories_debian.jpg',
                'distimage': 'images/distros-large/debian-large.png'
            },
            'deblts': {
                'float_fulltext': 'images/distros/ls_advisories_debianlts.jpg',
                'distimage': 'images/distros-large/debianlts-large.png'
            },
            'fedora': {
                'float_fulltext': 'images/distros/ls_advisories_fedora.jpg',
                'distimage': 'images/distros-large/fedora-large.png'
            },
            'gentoo': {
                'float_fulltext': 'images/distros/ls_advisories_gentoo.jpg',
                'distimage': 'images/distros-large/gentoo-large.png'
            },
            'rockylinux': {
                'float_fulltext': 'images/distros/ls_advisories_rockylinux.jpg',
                'distimage': 'images/distros-large/rockylinux.png'
            },
            'mageia': {
                'float_fulltext': 'images/distros/ls_advisories_mageia.jpg',
                'distimage': 'images/distros-large/mageia-large.png'
            },
            'opensuse': {
                'float_fulltext': 'images/distros/ls_advisories_opensuse.jpg',
                'distimage': 'images/distros-large/opensuse-large.png'
            },
            'oracle': {
                'float_fulltext': 'images/distros/ls_advisories_oracle.jpg',
                'distimage': 'images/distros-large/oracle-large.png'
            },
            'redhat': {
                'float_fulltext': 'images/distros/ls_advisories_redhat.jpg',
                'distimage': 'images/distros-large/redhat-large.png'
            },
            'scientific': {
                'float_fulltext': 'images/distros/ls_advisories_scientificlinux.jpg',
                'distimage': 'images/distros-large/scientific-large.png'
            },
            'slackware': {
                'float_fulltext': 'images/distros/ls_advisories_slackware.jpg',
                'distimage': 'images/distros-large/slackware-large.png'
            },
            'suse': {
                'float_fulltext': 'images/distros/ls_advisories_suse.jpg',
                'distimage': 'images/distros-large/suse-large.png'
            },
            'ubuntu': {
                'float_fulltext': 'images/distros/ls_advisories_ubuntu.jpg',
                'distimage': 'images/distros-large/ubuntu-large.png'
            }
        }
        
        default = {
            'float_fulltext': 'null',
            'distimage': 'null'
        }
        
        return distro_images.get(os_name.lower(), default)

    def send_copy(self, title, intro_text, full_text, os_name):
        """Send copy notification email"""
        try:
            cmd = ['/usr/sbin/sendmail', '-odb', '-t']
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
            
            email_content = f"""X-Script-Name: <gambit:~alerts/scripts/advisory.py>
From: alerts@guardiandigital.com
To: reports@guardiandigital.com
Subject: Automatically Inserted Advisory for {os_name}

The following advisory has been inserted into the database.
Please log into linuxsecurity.com, check the advisory and publish.

-Title: {title}

-Short Description:
{intro_text}

-Full Text:
{full_text}

-- Automatic Advisory Inserter"""
            
            proc.communicate(input=email_content)
        except Exception as e:
            print(f"Error sending copy email: {e}")

    def send_failed(self, title, os_name, error_reason=None):
        """Send failure notification email"""
        try:
            cmd = ['/usr/sbin/sendmail', '-odb', '-t']
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, text=True)
            
            # Build error details section
            error_details = ""
            if error_reason:
                error_details = f"\nError/Reason:\n{error_reason}\n"
            
            email_content = f"""X-Script-Name: <gambit:~alerts/scripts/advisory.py>
From: alerts@guardiandigital.com
To: dwreski@guardiandigital.com
Subject: {os_name} Advisory insert failed

The following advisory failed to be inserted.

subject: {title}
{error_details}
-- Automatic Advisory Inserter"""
            
            proc.communicate(input=email_content)
        except Exception as e:
            print(f"Error sending failure email: {e}")

    def insert_advisory(self, title_init, intro_text_init, full_text_init, os_name_init, adv_date_tz_init):
        """Insert advisory into database"""
        
        # Log to file
        db_file = '/home/alerts/scripts_linstage/db-record.txt'
        try:
            with open(db_file, 'a') as f:
                datestring = datetime.now().strftime('%c')
                f.write(f"BEGIN {datestring} -------------------------------------------------------------------------------------------\n")
                f.write(f"Title: {title_init} Date: {adv_date_tz_init}\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")

        if not full_text_init:
            error_msg = "Advisory fulltext is empty or null"
            self.send_failed(title_init, os_name_init, error_msg)
            try:
                with open(db_file, 'a') as f:
                    f.write(f"Fulltext {title_init} null\n")
            except Exception as e:
                print(f"Error writing to log file: {e}")
            raise ValueError("fulltext null")

        databases = ["lsv7", "lsv7j5beta"]
        
        for dbname in databases:
            # Reset values for each database
            title = title_init
            intro_text = intro_text_init
            full_text = full_text_init
            os_name = os_name_init
            adv_date_tz = adv_date_tz_init

            connection = self.db_connect(dbname)
            if not connection:
                error_msg = f"Failed to connect to MySQL database: {dbname}"
                self.send_failed(title, os_name, error_msg)
                try:
                    with open(db_file, 'a') as f:
                        f.write(f"Failed to connect to MySQL database {title_init} null\n")
                except Exception as e:
                    print(f"Error writing to log file: {e}")
                raise Exception("failed to connect to MySQL database")

            cursor = connection.cursor()

            # Clean title
            title = re.sub(r'security and bug fix (update)?', '', title, flags=re.IGNORECASE)
            title_alias = self.clean_title_alias(title)

            # Parse date
            try:
                # Parse the date string
                dt = parsedate_to_datetime(adv_date_tz)
                newdate = dt.strftime('%Y-%m-%d %H:%M:%S')
                print(f"newdate: {newdate}")
            except Exception as e:
                print(f"Error parsing date: {e}")
                newdate = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Format full text
            full_text = f'<pre><font face="Courier">{full_text}</font></pre>'

            # Get category ID
            catid = self.get_catid(os_name)

            # Get distribution images
            images_info = self.get_distro_images(os_name)
            
            # Create JSON for images
            image_json = {
                'image_intro': images_info['float_fulltext'],
                'float_intro': '',
                'image_intro_alt': title,
                'image_intro_caption': title,
                'image_fulltext': images_info['distimage'],
                'float_fulltext': '',
                'image_fulltext_alt': title,
                'image_fulltext_caption': title,
            }

            attribs_json = {
                'helix_ultimate_image': images_info['distimage'],
            }

            # Check if title already exists
            check_sql = "SELECT id, title FROM xu5gc_content WHERE title = %s AND state = 1"
            cursor.execute(check_sql, (title,))
            existing = cursor.fetchone()
            
            if existing:
                already_exists = f"{os_name} title already exists: {existing[0]}"
                print(already_exists)
                with open(db_file, 'a') as f:
                    f.write(f"END {datestring} title already exists ----------------------------------------------------------------------\n")
                self.send_failed(already_exists, os_name, already_exists)
                cursor.close()
                self.db_disconnect(connection)
                return

            # Set access level based on database
            access = 1 if "lsv7j5beta" in dbname else 8

            # Insert into content table
            insert_sql = """
            INSERT INTO xu5gc_content (
                title, alias, introtext, `fulltext`, state, catid, created, created_by, 
                created_by_alias, modified, modified_by, checked_out, checked_out_time, 
                publish_up, publish_down, images, urls, attribs, version, ordering, 
                metakey, metadesc, metadata, access, hits, language
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """

            values = (
                title, title_alias, intro_text, full_text, 1, catid, newdate, 62,
                'LinuxSecurity.com Team', '0000-00-00 00:00:00', 0, 0, '0000-00-00 00:00:00',
                newdate, None, json.dumps(image_json), '', json.dumps(attribs_json), 1, 1,
                '', '', '{"robots":"","author":"","rights":"","xreference":""}', access, 1, '*'
            )

            print(f"inserting: {title}, {title_alias}, {newdate}")

            cursor.execute(insert_sql, values)
            article_id = cursor.lastrowid

            # Handle assets table
            # Get category asset ID
            cursor.execute("SELECT id FROM xu5gc_assets WHERE name LIKE %s", (f"com_content.category.{catid}",))
            parent_id = cursor.fetchone()[0]

            # Get max lft value
            cursor.execute("SELECT MAX(lft) FROM xu5gc_assets WHERE parent_id = %s", (parent_id,))
            lft = cursor.fetchone()[0] + 2
            rgt = lft + 1

            # Insert asset
            asset_sql = """
            INSERT INTO xu5gc_assets (parent_id, level, name, title, rules, lft, rgt)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(asset_sql, (parent_id, 4, f"com_content.article.{article_id}", title, '{}', lft, rgt))
            asset_id = cursor.lastrowid

            # Update content with asset_id
            cursor.execute("UPDATE xu5gc_content SET asset_id = %s WHERE id = %s", (asset_id, article_id))

            # Insert workflow association
            cursor.execute("INSERT INTO xu5gc_workflow_associations VALUES (%s, %s, %s)", 
                         (article_id, 1, "com_content.article"))

            cursor.close()
            self.db_disconnect(connection)

        # Log completion
        with open(db_file, 'a') as f:
            f.write(f"END {datestring} -------------------------------------------------------------------------------------------\n")