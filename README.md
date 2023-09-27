# rcWinFileScan
#######################################################################

Red Crow Labs

#######################################################################

DESCRIPTION:

rcWinFileScan is PoC PowerShell script to analyze a specified directory to gather security information.
It performs the following actions:

- Recursively enumerates all files under a directory.
- Collects and outputs file permissions for every file and directory.
- Determines if the file is a PE.
- If so, it attempts to gather compile security options such as ASLR and DEP.
- Identifies if the file is used as a service, and if so, collects service permissions.
- Identified file architecture.
- Collects file size and hashes.

=========================================================================

INSTALL: 

Allow non-signed scripts (this has security implications).

    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

Download and install PESecurity.

    git clone https://github.com/NetSPI/PESecurity.git

From within PowerShell:

    Import-Module C:\bin\PESecurity\Get-PESecurity.psm1

Download and install rcWinFileScan:

    git clone https://github.com/redcrowlab/rcWinFileScan.git



=========================================================================

USAGE: 

From within PowerShell:

.\rcWinFileScan.ps1 -dirPath C:\path\to\dir

=========================================================================
