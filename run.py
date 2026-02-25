"""
Application entry point.
Run this file to start the NIDS application.
"""

import os
from app import create_app, db, socketio
from app.models import User, Alert, ActivityLog, UserSession, PasswordResetToken, TrafficDaily


# Create application
config_name = os.getenv('FLASK_CONFIG', 'development')
app = create_app(config_name)


@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print("Database initialized!")


@app.cli.command()
def create_admin():
    """Create an admin user."""
    from getpass import getpass

    username = input("Admin username: ")
    email = input("Admin email: ")
    password = getpass("Admin password: ")
    password2 = getpass("Confirm password: ")

    if password != password2:
        print("Passwords don't match!")
        return

    # Check if user exists
    if User.query.filter_by(username=username).first():
        print("Username already exists!")
        return

    if User.query.filter_by(email=email).first():
        print("Email already exists!")
        return

    # Create admin user
    admin = User(
        username=username,
        email=email,
        role='admin',
        is_active=True,
        is_confirmed=True
    )
    admin.set_password(password)

    db.session.add(admin)
    db.session.commit()

    print(f"Admin user '{username}' created successfully!")


@app.cli.command()
def cleanup_db():
    """Clean up expired sessions and tokens."""
    expired_sessions = UserSession.cleanup_expired()
    expired_tokens = PasswordResetToken.cleanup_expired()

    print(f"Cleaned up {expired_sessions} expired sessions")
    print(f"Cleaned up {expired_tokens} expired tokens")


@app.shell_context_processor
def make_shell_context():
    """Make database models available in flask shell."""
    return {
        'db': db,
        'User': User,
        'Alert': Alert,
        'ActivityLog': ActivityLog,
        'UserSession': UserSession,
        'PasswordResetToken': PasswordResetToken,
        'TrafficDaily': TrafficDaily
    }


if __name__ == '__main__':
    # Use SocketIO's run method instead of app.run()
    socketio.run(
        app,
        host=app.config.get('HOST', '0.0.0.0'),
        port=app.config.get('PORT', 5000),
        debug=app.config.get('DEBUG', True),
        use_reloader=False  # Disable reloader to prevent duplicate threads
    )
