#!/bin/bash

HOME_DIR='/home/reporter'
SHARED_DIR=$HOME_DIR'/shared'

# Prepare fonts
echo "Preparing fonts..."
cp ./fonts/* /usr/share/fonts/truetype/
fc-cache -f

echo 'Waiting for saver'
while [ "$(redis-cli -h orchestrator_redis_1 get saving_complete)" != "true" ]
do
    sleep 5
done
echo "Saver finished"

# No longer needed
redis-cli -h orchestrator_redis_1 del saving_complete

echo "Creating reporting folder..."
mkdir -p $SHARED_DIR/artifacts/reporting

# Create the Scorecard
cd $SHARED_DIR/artifacts/reporting/
$HOME_DIR/scorecard/generate_trustymail_scorecard.py $SHARED_DIR/include/agencies.csv -f

mkdir -p $SHARED_DIR/artifacts/reporting/trustymail_reports

# Generate agency reports
# TODO? Separate cyhy reports from non-cyhy reports
cd $SHARED_DIR/artifacts/reporting/trustymail_reports
$HOME_DIR/report/create_all_reports.py

# Archive artifacts folder
echo 'Archiving Results...'
mkdir -p $SHARED_DIR/archive/
cd $SHARED_DIR
TODAY=$(date +'%Y-%m-%d')
mv artifacts artifacts_$TODAY
tar -czf $SHARED_DIR/archive/artifacts_$TODAY.tar.gz artifacts_$TODAY/

# Clean up
echo 'Cleaning up'
rm -rf artifacts_$TODAY

# Let redis know we're done
# redis-cli -h orchestrator_redis_1 set trustymail_reporting_complete true
# This is the end of the line, so tell redis to shutdown
redis-cli -h orchestrator_redis_1 shutdown
