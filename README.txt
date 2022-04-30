Virus_Total_File_Scan.py requires two arguements:
-A <this is for the Virus Total API Key which you get when you sign up>
-H <this is for the file Hash which must be in either MD5 or SHA256 Formats>

This script will return the number of AV Engines that Virus Total flagged as malicious
More than 5 flagged AV Engines is considered a Malicious File
Between 1 and 5 flagged AV Engines is considered a possible Malicious File
0 flagged AV Engines is considered a clean File

The reverse_backdoor.py is a backdoor that I wrote in python which I then uploaded to virus total.
8 AV Engines flagged this file as malicious
You can take an MD5 or SHA256 hash of this file to test the script