#!/bin/bash

HOME_DIR='/home/cisa'
SHARED_DIR=$HOME_DIR'/shared'

# Prepare fonts
echo "Preparing fonts..."
cp ./fonts/* /usr/share/fonts/truetype/
fc-cache -f

echo 'Waiting for saver'
while [ "$(redis-cli -h redis get saving_complete)" != "true" ]; do
  sleep 5
done
echo "Saver finished"

# Don't delete saving_complete here since pshtt_reporter may be using
# it too.  We let that container do the delete.  If that container
# isn't being used, though, then you'll want to uncomment the next
# line.
# redis-cli -h redis del saving_complete

echo "Creating reporting folder..."
mkdir -p $SHARED_DIR/artifacts/reporting/trustymail_reports

# Generate agency reports
# TODO? Separate cyhy reports from non-cyhy reports
cd $SHARED_DIR/artifacts/reporting/trustymail_reports || exit 1
$HOME_DIR/report/create_all_reports.py

# Again, we let pshtt_reporter do the archiving.  If that container
# isn't being used, though, then you'll want to uncomment the next
# block.

# Archive artifacts folder
# echo 'Archiving Results...'
# mkdir -p $SHARED_DIR/archive/
# cd $SHARED_DIR
# TODAY=$(date +'%Y-%m-%d')
# mv artifacts artifacts_$TODAY
# tar -czf $SHARED_DIR/archive/artifacts_$TODAY.tar.gz artifacts_$TODAY/
# Clean up
# echo 'Cleaning up'
# rm -rf artifacts_$TODAY

# Let redis know we're done.  We let the pshtt_reporter container do
# the actual shutdown.  If that container isn't being used, though,
# then you'll instead want to uncomment the shutdown line below.
redis-cli -h redis set trustymail_reporting_complete true

# This is the end of the line, so tell redis to shutdown
# redis-cli -h redis shutdown
