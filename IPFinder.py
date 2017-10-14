import json
import logging
import os
import re
import requests
import smtplib

IP_REGEX = re.compile(r'\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)'
                      r'{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b')


def query_ip(url):
    """ Finds the external IP address presented at URL.
    
    :param str url: A string representing the URL to find the IP within.
    
    :return: A string representing the URL if it was found, otherwise None. """

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as err:
        # Timeout error, DNS failure, refused connection, no connection... etc
        logging.warning("Error occurred while connecting to %s: %s" % (url, err))
        return None

    # Regex the entire page...
    ip = IP_REGEX.search(response.text)
    if ip is not None:
        ip = ip.group(0)

    return ip


def get_ip():
    """ Tries to find the external IP address for the device running this 
    module.
    
    :return str: A string representing the found IP. Otherwise None."""

    valid_sites = [
        'https://api.ipifyomom,.org/',
        'http://ident.me/',
        'http://myip.dnsomatic.com/',
        'http://www.trackip.net',
        'http://whatismyip.org',
        'https://www.iplocation.net/find-ip-address',
        'https://showip.net/',
        'https://ipinfo.info/html/ip_checker.php',
    ]

    for site in valid_sites:
        logging.info("Querying %s for external IP." % site)
        found_ip = query_ip(site)
        if not found_ip:
            logging.info("URL %s did not provide an external IP." % site)
            # Couldn't find the IP, try another site.
            continue
        return found_ip

    return None


def get_saved_ip(file_loc):
    """ Returns the IP saved from last use, if applicable. 
    
    :param str file_loc: The location of the file to be read from.
    :return str: The stored IP if it exists, otherwise None. """

    try:
        with open(file_loc) as file:
            return file.read()
    except FileNotFoundError:
        logging.info("No file is saved at %s." % file_loc)
        return None


def make_dirs(file_loc):
    """ Checks if the directories up to a file location exist and creates any
    if necessary.
     
    :param str file_loc: The path to a file including the filename itself. """

    file_dir = os.path.dirname(file_loc)
    if not os.path.exists(file_dir):
        os.makedirs(file_dir)


def update_saved_ip(found_ip, file_loc):
    """ Writes the found IP to a saved filed.
    
    :param str found_ip: The IP to save.
    :param str file_loc: The location of the file to be updated. """

    make_dirs(file_loc)

    with open(file_loc, "w") as file:
        file.write(found_ip)

    logging.info("Saved external IP successfully.")


def obtain_email_details(details_loc):
    """ Obtains the email details from the JSON file at the specific location
    
    :param str details_loc: The location of the JSON file holding the email 
    details.
    
    :return dict: The email details are returned as a dict. """

    required_details = {'smtp_addr', 'from_addr', 'to_addr', 'from_pwd'}

    try:
        with open(details_loc) as json_file:
            details = json.load(json_file)
    except FileNotFoundError:
        message = "Error occurred while obtaining email details. File %s " \
                  "does not exist." % details_loc
        raise RuntimeError(message)
    except ValueError:
        message = "Error occurred while obtaining email details. File %s " \
                  "could not be parsed as JSON." % details_loc
        raise RuntimeError(message)

    # Remove redundant key/values.
    details = {key: details[key] for key in details if key in required_details}

    missing_keys = required_details.difference(set(details.keys()))

    if missing_keys:
        message = "Error occurred while obtaining email details. File %s is " \
                  "missing details: %s." % (details_loc, missing_keys)
        raise RuntimeError(message)

    return details


def email_ip(smtp_addr, from_addr, from_pwd, to_addr, found_ip):
    """ Use email_details to send an email containing the found_ip
    
    :param str smtp_addr: The smtp server we are using (e.g. smtp.gmail.com)
    :param str from_addr: The email address we are sending the email from.
    :param str from_pwd: The password of the 'from' address.
    :param str to_addr: The email address we are sending the mail to.
    :param str found_ip: The found IP address
    
    :return bool: A boolean indicating if the send was successful. """

    subject = "New IP %s detected" % found_ip

    email_text = "Subject: %s\nA new external IP of %s was detected from " \
                 "your Raspberry Pi. Have a great day handsome!" \
                 % (subject, found_ip)

    try:
        logging.info("Sending email to %s." % to_addr)
        with smtplib.SMTP_SSL(smtp_addr) as server_ssl:
            server_ssl.login(from_addr, from_pwd)
            server_ssl.sendmail(from_addr, to_addr, email_text)
    except smtplib.SMTPException as err:
        logging.error("Error occurred while sending email: %s" % err)
        return False

    return True


def start_logging(log_loc):
    """ Starts the logging at a specific location and level

    :param str log_loc: The file location to log to
    :param level: The logging level"""

    make_dirs(log_loc)
    logging.basicConfig(filename=log_loc, level=logging.INFO,
                        format='[%(levelname)s][%(asctime)s]: %(message)s')

if __name__ == '__main__':

    try:

        module_directory = os.path.dirname(os.path.abspath(__file__))

        # Initialise the logging.
        log_loc = os.path.join(module_directory, 'info/IPFinderLog.txt')
        start_logging(log_loc)

        logging.info("Starting external IP Finder.")

        # Obtain the email details.
        logging.info("Obtaining saved email details.")
        email_details_loc = os.path.join(module_directory,
                                         "info/email_details.json")
        email_details = obtain_email_details(email_details_loc)

        # Obtain the IP
        logging.info("Obtaining external IP.")
        found_ip = get_ip()
        if found_ip is None:
            # Unable to retrieve the IP address. Exit with failure.
            logging.error("No external IP was found. Exiting...")
            exit(-1)
        logging.info("External IP of %s found." % found_ip)

        # Get the saved IP. Will be None if there is none saved.
        logging.info("Obtaining saved external IP.")
        saved_ip_loc = os.path.join(module_directory, "info/saved_ip.txt")
        saved_ip = get_saved_ip(saved_ip_loc)

        if found_ip != saved_ip:
            # New IP found, email using the obtain details.
            logging.info("External IP found differs from saved IP of "
                         "%s. Sending email." % saved_ip)
            email_status = email_ip(found_ip=found_ip, **email_details)
            if not email_status:
                # Failed to send email. Exit with failure.
                logging.error("Could not send email. Exiting...")
                exit(-1)
            logging.info("Email sent successfully.")
            logging.info("Saving new external IP to file.")
            update_saved_ip(found_ip, saved_ip_loc)
        else:
            logging.info("External IP has not changed.")

        logging.info("Program execution successful. Exiting...")

    except Exception as err:
        logging.exception("Unexpected error occurred causing program "
                          "termination.")
        raise err
