import base64
import logging
import os
import user_agents
from urllib import parse as url_parse
from google.oauth2 import service_account
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from lib.auth487.common import AUTH_DEV_MODE
from lib.auth487.flask import get_remote_addr

NOTIFICATION_EMAIL_FROM = os.getenv('NOTIFICATION_EMAIL_FROM')
NOTIFICATION_EMAIL_TO = os.getenv('NOTIFICATION_EMAIL_TO')
GMAIL_CREDENTIALS_FILE = os.getenv('GMAIL_CREDENTIALS_FILE')

_cred_cache = {}


def send_new_login_notification(request, response):
    remote_addr = get_remote_addr(request)
    ua_data = user_agents.parse(request.headers.get('user-agent', ''))

    message = 'New login success\nIP: {}\nBrowser: {}'.format(remote_addr, ua_data)
    if AUTH_DEV_MODE:
        response.headers['X-Login-Message'] = url_parse.quote(message)

    send_notification('Auth 487: new login', message)


def send_notification(subject, text):
    if not is_enabled():
        return

    service = create_gmail_send_service()
    message = create_message(subject, text)
    send_message(service, message)


def is_enabled():
    if not NOTIFICATION_EMAIL_FROM or not NOTIFICATION_EMAIL_TO or not GMAIL_CREDENTIALS_FILE:
        logging.warning('No email or credentials so do not send')
        return False

    if not os.path.exists(GMAIL_CREDENTIALS_FILE):
        logging.warning('Credentials file does not exist so do not send')
        return False

    return True


def create_gmail_send_service():
    cache_key = (GMAIL_CREDENTIALS_FILE, NOTIFICATION_EMAIL_FROM)
    if cache_key in _cred_cache:
        return _cred_cache[cache_key]

    scopes = ['https://www.googleapis.com/auth/gmail.send']

    credentials = service_account.Credentials.from_service_account_file(GMAIL_CREDENTIALS_FILE, scopes=scopes)
    delegated_credentials = credentials.with_subject(NOTIFICATION_EMAIL_FROM)

    service = _cred_cache[cache_key] = build('gmail', 'v1', credentials=delegated_credentials, cache_discovery=False)
    return service


def create_message(subject, message_text):
    message = MIMEText(message_text)

    message['to'] = NOTIFICATION_EMAIL_TO
    message['from'] = NOTIFICATION_EMAIL_FROM
    message['subject'] = subject

    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')}


def send_message(service, message):
    return service.users().messages().send(userId=NOTIFICATION_EMAIL_FROM, body=message).execute()
