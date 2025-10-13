# Employee-Offboarding-Scripts

Automated system for managing terminated employee account lifecycle in Active Directory.

## Features

- Automated account deactivation
- Risk assessment and scoring
- SIEM integration
- Multi-level logging
- SQLite database storage
- Email notifications

## Quick Start

1. Configure parameters in `$Config` section
2. Run script with appropriate permissions
3. Check logs in `C:\Audit\IdentityLifecycle`

## Requirements

- ActiveDirectory PowerShell module
- PSSQLite module
- Appropriate AD permissions