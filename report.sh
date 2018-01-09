#!/bin/bash
SHARED_DIR='/home/shared'

# Prepare fonts
echo "Preparing fonts..."
cp $SHARED_DIR/fonts/* /usr/share/fonts/truetype/
fc-cache -f

echo 'Waiting for trustymail results to be saved to database...'
while true;
do
  if [[ -r $SHARED_DIR/results_saved_to_db ]]
  then
    echo 'Trustymail results saved to database!'
    break
  fi
  sleep 5
done

echo "Creating reporting folder..."
mkdir -p $SHARED_DIR/artifacts/reporting

# Create the Scorecard
cd $SHARED_DIR/artifacts/reporting/
/home/scanner/scorecard/generate_trustymail_scorecard.py $SHARED_DIR/include/agencies.csv -f

mkdir -p $SHARED_DIR/artifacts/reporting/reports

# HTTPS reports only:
# Because HHS/NASA reports are large, we need to increase buffer size (LaTeX)
# sed -i 's/buf_size = 200000/buf_size = 400000/' /usr/share/texmf/web2c/texmf.cnf

# Generate agency reports
# TODO? Separate cyhy reports from non-cyhy reports
cd $SHARED_DIR/artifacts/reporting/reports
/home/scanner/report/create_all_reports.py

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
rm $SHARED_DIR/results_saved_to_db
