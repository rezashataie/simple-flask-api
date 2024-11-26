from flask import render_template
from flask_mail import Message
from app import mail
import logging


def send_email(subject, recipients, template_name, template_data):
    try:
        html_content = render_template(f"emails/{template_name}.html", **template_data)

        msg = Message(
            subject=subject,
            recipients=recipients,
            html=html_content,
        )
        mail.send(msg)
        logging.info(f"Email sent successfully to {recipients}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {recipients}: {e}")
        return False
