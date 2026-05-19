import datetime

from classes.email_sender import EmailSender

def compose_trailer():
    html_trailer = """
    <p class="body">Good luck!
        <span style="display: flex; align-items: center; gap: 0px;" class="body">
            <img src="https://api.safexs.eu:8000/images/Safe-XS-transparant-blue.png" alt="SafeXS Logo" width="50" height="50">The SafeXS Team
        </span>
    </p>
    """
    return html_trailer

def compose_features(date_from: datetime, date_to: datetime, offline: bool, remote: bool, admin: bool, send_keys: int):
    html_features = ""
    if (date_from or date_to or offline or remote or admin):
        html_features = """
        <p class=\"body\">You can use SafeXS:</p>
        <ul>
        """
        if date_from:
            html_features += f"""
            <li>from: {date_from}</li>
            """
        if date_to:
            html_features += f"""
            <li>up to: {date_to}</li>
            """
        if offline:
            html_features += """
            <li>in Offline mode without an Internet connection</li>
            """
        if remote:
            html_features += """
            <li>to open the lock remotely</li>
            """
        if admin:
            html_features += """
            <li>in Admin mode to manage this lock</li>
            """
        if send_keys:
            html_features += f"""
            <li>with {send_keys} additional key{"s" if send_keys > 2 else ""} to distribute</li>
            """

        html_features += """
        </ul>
        """
    return html_features

# Send 2FA token email
def send_2fa_token_email(to_email: str, message: str):
    # 2FA token email templates
    html_template = """
    <p class="body">Your 2FA code is:</p>
    <p class="header">{message}</p>
    """

    plain_template = """
    Your 2FA code is:
    {message}
    """

    # Parameters for the 2FA email
    params = {
        "message": message  # 2FA token
    }

    # Send 2FA token email
    EmailSender.send_email(
        to_email=to_email,
        subject="Your 2FA Code",
        html_template=html_template,
        plain_template=plain_template,
        params=params
    )

# Send new password email
def send_new_password_email(to_email: str, message: str, dear_text: str):
    # New password email templates
    html_template = """
    <p class="body">{dear_text},</p>
    <p class="body">
        It’s good that you have changed your password. Please keep it safe and delete this email message.<br>
        Your new password is:
    </p>
    <p class="body"><span class="highlight">{message}</span></p>
    """
    html_template += compose_trailer()

    plain_template = """
    {dear_text}

    Good you changed your password! Please keep it safe and delete this email message.
    Your new password is:

    {message}

    Good luck!
    The SafeXS Team
    """

    # Parameters for the new password email
    params = {
        "dear_text": dear_text,
        "message": message
    }

    # Send new password email using EmailSender class
    EmailSender.send_email(
        to_email=to_email,
        subject="Your New Password",
        html_template=html_template,
        plain_template=plain_template,
        params=params
    )

# Send new user invitation email
def send_invitation_email(to_email: str, from_email: str, lock_name: str, password: str, dear_text: str, features: str):
    html_template = """
    <p class="body">Welcome to SafeXS {dear_text}</p>
    <p class="body">You have been invited by {from_email} to open the lock of <strong>{lock_name}</strong>.</p>
    """
    html_template += features
    html_template += """
    <p class="body">If you didn't already download the SafeXS app, you can get it from:</p>
    <ul>
        <li><a href="https://apps.apple.com/app/safexs/id6741073730">Apple App Store</a> (iOS)</li>
        <li><a href="https://play.google.com/store/apps/details?id=eu.safexs.android">Google Play Store</a> (Android)</li>
    </ul>
    <p class="body">When you log in to the SafeXS app use these credentials:</p>
    <ul>
        <li>email: {to_email}</li>
        <li>password: <span class="highlight">{password}</span></li>
    </ul>
    """
    html_template += compose_trailer()

    plain_template = """
    Welcome to SafeXS {dear_text}

    You have been invited by {from_email} to open the lock of "{lock_name}".

    If you didn't already download the SafeXS app:

    - https://apps.apple.com/app/safexs/id6741073730 (Apple App Store)
    - https://play.google.com/store/apps/details?id=eu.safexs.android (Google Play Store)

    Login credentials:

    - email: {to_email}
    - password: {password}

    Good luck!
    The SafeXS Team
    """

    params = {
        "dear_text": dear_text,
        "from_email": from_email,
        "lock_name": lock_name,
        "to_email": to_email,
        "password": password
    }

    # Send email
    EmailSender.send_email(
        to_email=params["to_email"],
        subject= f"SafeXS Invitation For {lock_name}",
        html_template=html_template,
        plain_template=plain_template,
        params=params
    )

# Send invitation to existing user for new lock
def send_confirmation_email(to_email: str, from_email: str, lock_name: str, dear_text: str, features: str):
    # Confirmation email templates
    html_template = """
    <p class="body">{dear_text},</p>
    <p class="body">You have granted access by {from_email} to <strong>{lock_name}</strong>.</p>
    """
    html_template += features
    html_template += """
    <p class="body">If you didn't already download the SafeXS app, you can get it from:</p>
    <ul>
        <li><a href="https://apps.apple.com/app/safexs/id6741073730">Apple App Store</a> (iOS)</li>
        <li><a href="https://play.google.com/store/apps/details?id=eu.safexs.android">Google Play Store</a> (Android)</li>
    </ul>
    <p class="body">To log into the SafeXS app, use the following:</p>
    <ul>
        <li>email: {to_email}</li>
        <li>password: &lt;your password&gt; or press 'Create new password'</li>
    </ul>   
    """
    html_template += compose_trailer()

    plain_template = """
    {dear_text},

    You have granted access by {from_email} to "{lock_name}".

    If you didn't already download the SafeXS app:

    - https://apps.apple.com/app/safexs/id6741073730 (Apple App Store)
    - https://play.google.com/store/apps/details?id=eu.safexs.android (Google Play Store)

    To log into the SafeXS app:

    - email: {to_email}
    - password: <your password> or press 'Create new password'

    Good luck!
    The SafeXS Team
    """

    # Parameters for the confirmation email
    params = {
        "dear_text": dear_text,
        "from_email": from_email,
        "lock_name": lock_name,
        "to_email": to_email
    }

    # Send confirmation email using EmailSender class
    EmailSender.send_email(
        to_email=params["to_email"],
        subject=f"SafeXS Access For {lock_name}",
        html_template=html_template,
        plain_template=plain_template,
        params=params
    )

# Send new user invitation email
def send_new_user_email(to_email: str, from_email: str, password: str, dear_text: str):
    html_template = """
    <p class="body">Welcome to SafeXS {dear_text}</p>
    <p class="body">You have been invited by {from_email} to use the SafeXS app for secure access.</p>
    """
    html_template += """
    <p class="body">If you didn't already download the SafeXS app, you can get it from:</p>
    <ul>
        <li><a href="https://apps.apple.com/app/safexs/id6741073730">Apple App Store</a> (iOS)</li>
        <li><a href="https://play.google.com/store/apps/details?id=eu.safexs.android">Google Play Store</a> (Android)</li>
    </ul>
    <p class="body">When you log in to the SafeXS app use these credentials:</p>
    <ul>
        <li>email: {to_email}</li>
        <li>password: <span class="highlight">{password}</span></li>
    </ul>
    """
    html_template += compose_trailer()

    plain_template = """
    Welcome to SafeXS {dear_text}

    You have been invited by {from_email} to use the SafeXS app for secure access.

    If you didn't already download the SafeXS app:

    - https://apps.apple.com/app/safexs/id6741073730 (Apple App Store)
    - https://play.google.com/store/apps/details?id=eu.safexs.android (Google Play Store)

    Login credentials:

    - email: {to_email}
    - password: {password}

    Good luck!
    The SafeXS Team
    """

    params = {
        "dear_text": dear_text,
        "from_email": from_email,
        "to_email": to_email,
        "password": password
    }

    # Send email
    EmailSender.send_email(
        to_email=params["to_email"],
        subject= f"SafeXS Invitation For Secure Access",
        html_template=html_template,
        plain_template=plain_template,
        params=params
    )
