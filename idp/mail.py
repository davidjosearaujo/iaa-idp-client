import base64
from email.mime.text import MIMEText
import sys
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from requests import HTTPError

class IdP_email:
    def __init__(self):
        SCOPES = [
                "https://www.googleapis.com/auth/gmail.send"
            ]
        flow = InstalledAppFlow.from_client_secrets_file('client.json', SCOPES)
        creds = flow.run_local_server(port=42303)
        self.service = build('gmail', 'v1', credentials=creds)

    def send_otp(self, otp: str, destination: str):
        email_body = f"""
                    <html>
                    <body>
                        <p>Use the following code to validate your identity:</p>
                        <p><strong>{otp}</strong></p>
                        <p>This code will expire in 5 minutes.</p>
                        <p>This email was automatically sent, please don't reply.</p>
                    </body>
                    </html>
                    """
        message = MIMEText(email_body, "html")
        message['to'] = destination
        message['subject'] = 'IAA IdP OTP'
        formatted_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

        try:
            message = (self.service.users().messages().send(userId="me", body=formatted_message).execute())
            return True
        except HTTPError as error:
            print(error, file=sys.stderr)
            return False
        
    def send_registration_link(self, url: str, destination: str):
        email_body = f"""
                    <html>
                    <body>
                        <p>Access the following link to finish your registration:</p>
                        <p><strong>{url}</strong></p>
                        <p>This email was automatically sent, please don't reply.</p>
                    </body>
                    </html>
                    """
        message = MIMEText(email_body, "html")
        message['to'] = destination
        message['subject'] = 'IAA IdP registration'
        formatted_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

        try:
            message = (self.service.users().messages().send(userId="me", body=formatted_message).execute())
            return True
        except HTTPError as error:
            print(error, file=sys.stderr)
            return False