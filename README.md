# smtptx

## Introduction

This very simple tool is used for sending simple email and  do some basic email testing from a pentester perspective. Its able to send messages without depending on an specific MTA/SMTP server. Unlike tools like sendemail it handles the MX record resolution itself and connects to the relevant server and sends the email. Knowing the address of the specific SMTP server is thus not necessary.

## Functions

usage: smtptx.py [-h] [-t TO_ADDRESS] [-f FROM_ADDRESS] [-s SUBJECT] [-m MESSAGE_BODY] [-a ATTACHMENT] [-u USERNAME] [-p PASSWORD] [--use-tls] [-d DNS_SERVER] [--dns-timeout DNS_TIMEOUT] [-S SMTP_SERVER]
                 [--smtp-timeout SMTP_TIMEOUT] [-P SMTP_PORT] [--source-host SOURCE_HOST] [-r] [-e EHLO_HOST] [-T TO_LIST] [-F FROM_LIST] [--flood FLOOD] [-v]

SMTPTX v2.1 Alpha

optional arguments:
  -h, --help            show this help message and exit
  -t TO_ADDRESS, --to TO_ADDRESS
                        To address
  -f FROM_ADDRESS, --from FROM_ADDRESS
                        From address
  -s SUBJECT, --subject SUBJECT
                        Mail subject - Be creative
  -m MESSAGE_BODY, --message MESSAGE_BODY
                        Message body - Be more creative
  -a ATTACHMENT, --attachment ATTACHMENT
                        File to attach
  -u USERNAME, --username USERNAME
                        Username for SMTP authentication
  -p PASSWORD, --password PASSWORD
                        Password for SMTP authentication
  --use-tls             Use TLS link encryption
  -d DNS_SERVER, --dns DNS_SERVER
                        Use custom DNS server for MX and A record resolution
  --dns-timeout DNS_TIMEOUT
                        Set timeout value for DNS queries, default is 5s
  -S SMTP_SERVER, --smtp-server SMTP_SERVER
                        Use a specific SMTP server instead of a resolved one
  --smtp-timeout SMTP_TIMEOUT
                        Set a timeout value for SMTP connections, default is 10 seconds
  -P SMTP_PORT, --smtp-port SMTP_PORT
                        Use non-standard SMTP port, default is 25
  --source-host SOURCE_HOST
                        Use a custom source host in MIME encoding
  -r, --resolve-only    Resolve address/IP only. Do not send email
  -e EHLO_HOST, --ehlo EHLO_HOST
                        Set custom ESMTP EHLO
  -T TO_LIST, --to-list TO_LIST
                        A file containing a list of email addresses, one per row
  -F FROM_LIST, --from-list FROM_LIST
                        A file containing a list of email addresses, one per row
  --flood FLOOD         Number of copies of the message to send, default is 1
  -v, --verbose         Add verbosity to screen/log output


Do note that all functions are not implemented.
