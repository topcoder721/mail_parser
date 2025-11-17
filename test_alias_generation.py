#!/usr/bin/env python3
"""Test script to compare AI-generated aliases vs old approach"""

import re

# Test cases with long titles
test_titles = [
    "DSA-6059-1 thunderbird - security update",
    "Debian DSA-6059-1 : thunderbird - security update",
    "FEDORA-2024-123 kernel security and bug fix update",
    "openSUSE-SU-2024:0123-1: Security update for chromium",
    "Ubuntu USN-1234-1: Apache HTTP Server vulnerabilities",
    "[SECURITY] [DLA 3456-1] nginx security update",
    "openSUSE: 2025:3744-1 : aws-cli, local-npm-registry, python-boto3, python-botocore, python-coverage, python-flaky, python-pluggy, python-pytest, python-pytest-cov, python-pytest-html, python-pytest-metada",
]

def old_clean_title_alias(title):
    """Old approach - just removing unwanted terms"""

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
    
    return alias.strip()

def new_clean_title_alias(title):
    """New AI approach - imported from advisory.py"""
    from advisory import Advisory
    advisory = Advisory()
    alias = advisory.clean_title_alias(title)
    # Remove random ID for comparison
    return '-'.join(alias.split('-')[:-1])

def test_comparison():
    """Compare old vs new approach"""
    print("COMPARISON: Old Approach vs AI-Powered Approach")
    print("=" * 100)
    
    for title in test_titles:
        old_alias = old_clean_title_alias(title)
        new_alias = new_clean_title_alias(title)
        
        print(f"\nTitle: {title[:80]}{'...' if len(title) > 80 else ''}")
        print(f"  OLD: {old_alias} ({len(old_alias)} chars)")
        print(f"  NEW: {new_alias} ({len(new_alias)} chars)")
        
        savings = len(old_alias) - len(new_alias)
        if savings > 0:
            print(f"  ✓ SHORTER by {savings} chars ({int(savings/len(old_alias)*100)}% reduction)")
        elif savings < 0:
            print(f"  ⚠ LONGER by {abs(savings)} chars")
        else:
            print(f"  = SAME length")

if __name__ == "__main__":
    test_comparison()
