from flask import render_template
from flask_mail import Message
from app import mail
import logging


class EmailService:
    """
    A service class for managing email sending operations.
    """

    @staticmethod
    def send(subject, recipients, template_name, template_data):
        """
        Send an email with the specified template.
        :param subject: Subject of the email.
        :param recipients: List of email addresses to send the email to.
        :param template_name: Name of the email template (without extension).
        :param template_data: Dictionary of data to render the template.
        :return: True if email sent successfully, False otherwise.
        """
        try:
            # Render the HTML content from the template
            html_content = render_template(
                f"emails/{template_name}.html", **template_data
            )

            # Create the email message
            msg = Message(
                subject=subject,
                recipients=recipients,
                html=html_content,
            )

            # Send the email
            mail.send(msg)
            logging.info(f"Email sent successfully to {recipients}")
            return True
        except Exception as e:
            logging.error(f"Failed to send email to {recipients}: {e}")
            return False
