Don't want to pay your service provider for that static IP? This is a simple script that queries a few URLs for your current external IP, and then emails you if a new one was found.

Ideally a cronjob would be set-up to run this script every few minutes or so.

The process logs automatically to info/IPFinderLog.txt.

Set-up is simple:

1) sudo pip install -r requirements.txt
2) Add your email details to info/email_details.json
3) Set-up a cronjob to run the script (optional)