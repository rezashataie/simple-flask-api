from flask_mail import Message
from app import mail
import logging

def send_email(subject, recipients, body, html=None):
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=body,
            html=html,
        )
        mail.send(msg)
        logging.info(f"Email sent successfully to {recipients}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {recipients}: {e}")
        return False
