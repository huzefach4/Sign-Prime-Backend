from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import os
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import certifi

def send_signature_email(to_email, subject, html_content):

    message = Mail(
        from_email=(
            os.getenv("SENDGRID_FROM_EMAIL"),
            os.getenv("SENDGRID_FROM_NAME")
        ),
        to_emails=to_email,
        subject=subject,
        html_content=html_content
    )

    try:

        ssl_context = ssl.create_default_context(
            cafile=certifi.where()
        )

        sg = SendGridAPIClient(
            os.getenv("SENDGRID_API_KEY")
        )

        response = sg.send(message)

        print("Email sent:", response.status_code)
        return True

    except Exception as e:
        print("SendGrid Error:", str(e))
        return False