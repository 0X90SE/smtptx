#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ==============================================================================
# Title        :   SMTPTX
# Dependencies :   Python v3.x and Python DNS Toolkit (www.dnspython.org)
# Version      :   2.1 Beta
# Author       :   Copyright (c) 2017 <circle@0x90.se>, http://www.0x90.se
# Thanks/Creds :
# Abstract     :   This very simple tool is used for sending simple email and
#                  do some basic email testing from a pentester perspective.
#                  Its able to send messages without depending on an specific
#                  MTA/SMTP server. Unlike tools like sendemail it handles the
#                  MX record resolution itself and connects to the relevant
#                  server and sends the email. Knowing the address of the
#                  specific SMTP server is thus not necessary.
#
# License      :   This code is free and released under the terms of GPL v3
#
# Issues       :   First pre-production == Some issues do exist and functions
#                  ARE missing. It is NOT very fault tolerant at all!
#                  The basic stuff seem to work, no extensive tests has been
#                  done! The code has been tested only on Linux (Debian & Kali)
#
# Todo         :   Near future improvements:
#                  - Ability to accept domain only when resolving SMTP servers
#                    and not rely on a full email address
#                  - Add custom EHLO host, VRFY and the like options
#                  - Add logging to file
#                  - Add 'quiet' option in order to suppress all output
# Todo         :   Later improvements:
#                  - Structure the code in a better manner
#                  - Perhaps add interactive mode
#
# Change log   :   Initial release == Bugs for sure!
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND ANY CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR ANY CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# THIS PROGRAM MAY NOT BE USED IN ANY ILLEGAL ACTIVITIES!
#
# ==============================================================================


import os
import re
import sys
import time
import email
import smtplib
import argparse
import email.utils

from argparse import RawTextHelpFormatter

from email import utils
from email import encoders
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText


class ArgParser(object):

    def parse_args(self):

        parser = argparse.ArgumentParser(description="""SMTPTX v2.1 Alpha""",
                                         epilog="\n",
                                         add_help=True,
                                         formatter_class=RawTextHelpFormatter)

        parser.add_argument("-t", "--to",
                            dest="to_address",
                            help="To address",
                            required=False)

        parser.add_argument("-f", "--from",
                            dest="from_address",
                            help="From address",
                            required=False)

        parser.add_argument("-s", "--subject",
                            dest="subject",
                            help="Mail subject - Be creative",
                            required=False)

        parser.add_argument("-m", "--message",
                            dest="message_body",
                            help="Message body - Be more creative",
                            required=False)

        parser.add_argument("-a", "--attachment",
                            dest="attachment",
                            help="File to attach",
                            required=False)

        parser.add_argument("-u", "--username",
                            dest="username",
                            help="Username for SMTP authentication",
                            required=False)

        parser.add_argument("-p", "--password",
                            dest="password",
                            help="Password for SMTP authentication",
                            required=False)

        parser.add_argument("--use-tls",
                            dest="use_tls",
                            help="Use TLS link encryption",
                            action="store_true",
                            required=False)

        parser.add_argument("-d", "--dns",
                            dest="dns_server",
                            help="Use custom DNS server for MX and A record resolution",
                            required=False)

        parser.add_argument("--dns-timeout",
                            dest="dns_timeout",
                            help="Set timeout value for DNS queries, default is 5s",
                            required=False,
                            default=5)

        parser.add_argument("-S", "--smtp-server",
                            dest="smtp_server",
                            help="Use a specific SMTP server instead of a resolved one",
                            required=False)

        parser.add_argument("--smtp-timeout",
                            dest="smtp_timeout",
                            help="Set a timeout value for SMTP connections, default is 10 seconds",
                            required=False,
                            default=10)

        parser.add_argument("-P", "--smtp-port",
                            dest="smtp_port",
                            help="Use non-standard SMTP port, default is 25",
                            required=False,
                            default=25)

        parser.add_argument("--source-host",
                            dest="source_host",
                            help="Use a custom source host in MIME encoding",
                            required=False)

        parser.add_argument("-r", "--resolve-only",
                            dest="resolve",
                            help="Resolve address/IP only. Do not send email",
                            required=False,
                            action="store_true",
                            default=False)

        parser.add_argument("-e", "--ehlo",
                            dest="ehlo_host",
                            help="Set custom ESMTP EHLO",
                            required=False)

        parser.add_argument("-T", "--to-list",
                            dest="to_list",
                            help="A file containing a list of email addresses, one per row",
                            required=False)

        parser.add_argument("-F", "--from-list",
                            dest="from_list",
                            help="A file containing a list of email addresses, one per row",
                            required=False)

        parser.add_argument("--flood",
                            dest="flood",
                            help="Number of copies of the message to send, default is 1",
                            required=False,
                            default=1)

        parser.add_argument("-v", "--verbose",
                            dest="verbose",
                            help="Add verbosity to screen/log output",
                            required=False,
                            action="store_true",
                            default=False)

        return parser.parse_args()


class SMTPTX(object):
    """
    Class to send email without an MTA or relay
    """

    mail_domain = None
    smtp_servers = []
    flood = 1

    def add_attachment(self, args, email_message):
        """

        :param args:
        :param email_message:
        :return:
        """

        part = MIMEBase('application', 'octet-stream')

        try:
            attachment = open(args.attachment, "rb")

            attachment.seek(0, 2)
            print("[*]  Attachment file size: {}".format(attachment.tell()))

        # As a part of maintaining OPSEC, the script will terminate if attachment fails.
        # This is better than a phishing/social engineering campaign going bad
        except IOError as file_error:
            print("[-]  Unable to open attachment file! Reason:")
            print("     {}".format(file_error))
            sys.exit(1)

        part.set_payload(attachment.read())

        try:
            attachment.close()
        except IOError as file_error:
            print("[-]  Failed to close the attachment file! Reason:")
            print("     {}".format(file_error))

        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment filename={}'.format(os.path.basename(args.attachment)))
        email_message.attach(part)

    def resolve_mx(self, args):

        resolver = dns.resolver.Resolver()

        resolver.timeout = args.dns_timeout
        resolver.lifetime = args.dns_timeout

        print()

        if args.dns_server:
            print("[*]  Using custom DNS server: {}".format(args.dns_server))
            resolver.nameservers = [args.dns_server]

        if args.to_address:
            match_domain = re.match(r'[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', args.to_address, re.M | re.I)
            self.mail_domain = match_domain.group(1)

            print("[*]  Resolving MX records for: {}".format(self.mail_domain))

        else:
            print("[!]  No \"To\" address given...")

        try:
            if self.mail_domain:
                mx_query = dns.resolver.query(self.mail_domain, 'MX')

        except dns.exception.DNSException as dns_error:
            print("[-]  Not able to resolve the MX record. Reason:")
            print("[-]  {}".format(dns_error))

        print("[+]  Resolved {} SMTP host(s): ".format(len(mx_query)))

        for mx_data in mx_query:
            mx_record = repr(mx_data.exchange)
            mx_string = re.match(r'<DNS name (.*)\.>$', mx_record, re.M | re.I)
            mx_host = mx_string.group(1)

            try:
                a_query = dns.resolver.query(mx_host, 'A')[0].address

            except dns.exception.DNSException as dns_error:
                print("[-]  Not able to resolve the MX record. Reason:")
                print("[-]  {}".format(dns_error))

            print("     * {} -> {}".format(mx_host, a_query))
            self.smtp_servers.append(mx_host)

        return True

    def send_email(self, args):
        """

        :return:
        """

        if args.flood:
            self.flood = args.flood

        email_message = MIMEMultipart()
        email_message['To'] = email.utils.formataddr(('', args.to_address))
        email_message['from'] = email.utils.formataddr(('', args.from_address))
        email_message['Subject'] = args.subject
        email_message.attach(MIMEText(args.message_body))

        if args.attachment:
            self.add_attachment(args, email_message)

        if args.verbose:
            print("[+]  Connecting to SMTP server: {}:{}".format(self.smtp_servers[0], args.smtp_port))

        try:
            smtp_handler = smtplib.SMTP(self.smtp_servers[0], args.smtp_port, timeout=int(args.smtp_timeout))
            smtp_handler.set_debuglevel(args.verbose)
            smtp_handler.connect(self.smtp_servers[0], args.smtp_port)
            smtp_handler.ehlo(args.ehlo_host)

            if args.use_tls:

                if smtp_handler.has_extn('STARTTLS'):

                    try:
                        print("[+]  Server supports TLS! Using it...")
                        smtp_handler.starttls()

                    except smtplib.SMTPException as smtp_error:
                        print("[-]  Failed to negotiate TLS! Reason:")
                        print("[-]  {}".format(smtp_error))
                else:
                    print("[!]  Server does not seem to support TLS!")

                # Reidentify with EHLO over TLS
                smtp_handler.ehlo(args.ehlo_host)

            if args.username and args.password:
                if args.verbose:
                    print("[+]  Logging in")
                try:
                    smtp_handler.login(args.username, args.password)

                except smtplib.SMTPException:
                    print("[!]  Authentication failure!")
                    print("[¡]  Will try to ignore...")

            if args.verbose:
                print("[+]  Sending...")

            for copy in self.flood:
                smtp_handler.sendmail(args.from_address, args.to_address, email_message.as_string())
                sys.stdout.write("[*]  Copy {}/{} sent...".format(copy, self.flood), end="")
                sys.stdout.flush()

            smtp_handler.quit()

        except smtplib.SMTPException as smtp_error:
            print("[-]  Failure of biblical proportions! Unable to send mail! Reason:")
            print("[-]  {}".format(smtp_error))
            sys.exit(1)

        except smtplib.socket.error:
            print("[-]  Failure of biblical proportions! Socket timeout")
            sys.exit(1)

        return True


def main():
    """

    :return:
    """
    args = ArgParser().parse_args()

    mailer = SMTPTX()

    if mailer.resolve_mx(args):

        if mailer.send_email(args):
            print("[+]  Message sent!...")

    print()


if __name__ == "__main__":

    if sys.version_info[0] < 3:
        print()
        raise Exception("[-]  Python 3.x expected...")
        print()
        exit(1)

    try:
        import dns
        from dns import resolver
        from dns import exception

    except ImportError:
        print()
        print(" import Error: You seem to be missing the DNS Python Library!")
        print(" PIP: sudo pip install dnspython")
        print(" Fedora: sudo dnf install python3-dns")
        print(" Debian: sudo apt-get install python3-dnspython")
        print(" For more info: www.pythondns.org")
        print(" Exiting....")
        print()
        sys.exit(1)

    main()
