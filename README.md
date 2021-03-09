# sslscan-converter
Save the raw output from sslscan in a files with the extension ".sslscan". Save the output of one host per file. Point the script at the directory with the sslscan output and it will write to a file called "ssl_issues.csv", which contains a list of outdated or insecure SSL/TLS configurations.

This script is still in development, and only contains support for the most common ciphers. If you find an issue with the script (there are probably many), please raise an issue on this project.
