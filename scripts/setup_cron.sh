#!/bin/bash

# This script helps set up a cron job for automated PySpector scans.

echo "--- PySpector Cron Job Setup ---"

# Prompt for project path
read -p "Enter the full path to the project you want to scan: " PROJECT_PATH
if [ ! -d "$PROJECT_PATH" ]; then
    echo "Error: Directory not found."
    exit 1
fi

# Prompt for scan frequency
echo "Select scan frequency:"
echo "  1) Daily"
echo "  2) Weekly"
echo "  3) Monthly"
read -p "Enter choice [1]: " FREQ_CHOICE
FREQ_CHOICE=${FREQ_CHOICE:-1}

case $FREQ_CHOICE in
    1) CRON_SCHEDULE="0 2 * * *" ;; # 2 AM daily
    2) CRON_SCHEDULE="0 2 * * 0" ;; # 2 AM every Sunday
    3) CRON_SCHEDULE="0 2 1 * *" ;; # 2 AM on the 1st of every month
    *) echo "Invalid choice." ; exit 1 ;;
esac

# Prompt for report path
read -p "Enter path to store reports [/var/log/pyspector/]: " REPORT_PATH
REPORT_PATH=${REPORT_PATH:-/var/log/pyspector}

# Create report directory if it doesn't exist
sudo mkdir -p "$REPORT_PATH"
sudo chown "$(whoami)" "$REPORT_PATH"
echo "Report directory set to $REPORT_PATH"

# Get path to pyspector executable
PYDSPECTOR_CMD=$(which pyspector)
if [ -z "$PYDSPECTOR_CMD" ]; then
    echo "Error: 'pyspector' command not found in PATH."
    echo "Please ensure PySpector is installed and your PATH is configured correctly."
    exit 1
fi

# Create the cron job line
CRON_JOB="$CRON_SCHEDULE cd $PROJECT_PATH && $PYDSPECTOR_CMD scan . --format json --output $REPORT_PATH/report_\$(date +\%Y\%m\%d_\%H\%M\%S).json > /dev/null 2>&1"

echo ""
echo "--- Installation ---"
echo "To install the cron job, run 'crontab -e' and add the following line:"
echo ""
echo -e "\033[0;32m$CRON_JOB\033[0m"
echo ""
echo "This will run PySpector and save a JSON report to $REPORT_PATH."
