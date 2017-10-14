Don't want to pay your service provider for that static IP? This is a simple script that queries a few URLs for your current external IP, and then emails you if a new one was found.

Ideally a cronjob would be used to run this script every few minutes or so.

The process logs automatically to info/IPFinderLog.txt.

Set-up is simple:

1) sudo apt-get install python3 (if necessary).
2) sudo pip install -r requirements.txt (installs requests library).
3) Rename info/email_details_template.json to info/email_details.json and add your email details to it.
4) Set-up a cronjob to run the script (e.g. */10 * * * * python3 ~/IPFinder/IPFinder.py) (optional).