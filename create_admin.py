"""
Quick script to create an admin user.
Run this script to create the default admin account.
"""

import os
os.environ['FLASK_CONFIG'] = 'development'

from app import create_app, db
from app.models import User

# Create app
app = create_app()

with app.app_context():
    # Check if admin exists
    existing_admin = User.query.filter_by(username='admin').first()
    if existing_admin:
        print("[OK] Admin user already exists!")
        print(f"   Username: admin")
        print(f"   Email: {existing_admin.email}")
        print("\nYou can login with username 'admin' and your password.")
    else:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@nids.com',
            role='admin',
            is_active=True,
            is_confirmed=True
        )
        admin.set_password('admin123')  # Default password - CHANGE THIS!

        db.session.add(admin)
        db.session.commit()

        print("=" * 50)
        print("[SUCCESS] Admin user created successfully!")
        print("=" * 50)
        print(f"   Username: admin")
        print(f"   Email: admin@nids.com")
        print(f"   Password: admin123")
        print("=" * 50)
        print("\n[WARNING] IMPORTANT: Change the password after first login!")
        print("   Go to Profile > Change Password\n")
