import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class EmailSender:
    # Static configuration
    SMTP_SERVER = "smtp.titan.email"
    SMTP_PORT = 587
    SMTP_USER = "admin@safexs.eu"
    SMTP_PASSWORD = "dyrkif-qAjfaw-9zojju"

    # Static CSS styling
    CSS_STYLE = """
    <style>
        body {
            font-family: Arial, sans-serif;
        }
        .header {
            text-align: left;
            font-size: 16px;
            font-weight: bold;
            color: #116BFF;
        }
        .body {
            font-size: 16px;
            color: #333;
        }
        a:link {
            color: #116BFF;
            text-decoration: none;
            font-size: 16px;
        }
        a:visited {
            color: #777777;
            text-decoration: none;
            font-size: 16px;
        }
        ul {
            margin-top: 0.5em;
            padding-left: 20px;
        }
        li {
            margin-bottom: 8px;
            font-size: 16px;
        }
        .highlight {
            color: #116BFF;
        }
    </style>
    """

    @classmethod
    def send_email(cls, to_email: str, subject: str, html_template: str, plain_template: str, params: dict):
        try:
            # Fill in templates with parameters
            html_message = cls.CSS_STYLE + html_template.format(**params)
            plain_text_message = plain_template.format(**params)

            # Create MIME message
            msg = MIMEMultipart("alternative")
            msg["From"] = cls.SMTP_USER
            msg["To"] = to_email
            msg["Subject"] = subject

            # Attach plain-text and HTML versions
            msg.attach(MIMEText(plain_text_message, "plain"))
            msg.attach(MIMEText(html_message, "html"))

            # Send the email
            with smtplib.SMTP(cls.SMTP_SERVER, cls.SMTP_PORT) as server:
                server.starttls()
                server.login(cls.SMTP_USER, cls.SMTP_PASSWORD)
                server.send_message(msg)

        except smtplib.SMTPException as e:
            raise Exception(f"Failed to send email: {str(e)}")