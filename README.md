# Network Intrusion Detection System (NIDS)

A real-time network intrusion detection system using Machine Learning models (XGBoost, Random Forest and K-Nearest Neighbor) for threat detection and analysis.

## Features

- **Real-time Network Monitoring** - Captures and analyzes network traffic using Scapy
- **Machine Learning Detection** - Uses XGBoost for real-time threat classification with 20 CICIDS2017 features
- **PCAP File Analysis** - Upload and analyze PCAP files with all 3 ML models (XGBoost, Random Forest, KNN)
- **Web Dashboard** - Real-time alerts, statistics, and interactive visualizations via Socket.IO
- **Multi-Model Comparison** - Compare predictions from XGBoost, Random Forest, and K-Nearest Neighbors
- **User Management** - Complete authentication system with registration, login, profile management, and password reset
- **Admin Panel** - User management, activity monitoring, and system-wide statistics
- **Export Functionality** - Download analysis reports and results
- **Error Handling** - Custom error pages (403, 404, 429, 500) with user-friendly messages
- **Database Management** - SQLite with Alembic migrations support

## Tech Stack

- **Backend:** Flask, Flask-SocketIO, SQLAlchemy, Flask-Migrate (Alembic)
- **ML Models:** XGBoost, scikit-learn (Random Forest, KNN), pandas, numpy
- **Network Capture:** Scapy (pure Python implementation)
- **Database:** SQLite with Alembic migrations (production can use PostgreSQL/MySQL)
- **Frontend:** HTML5, CSS3, JavaScript (ES6+), Socket.IO client
- **Security:** Werkzeug password hashing, WTForms validation, CSRF protection
- **Logging:** Python logging module with file rotation
- **Development Tools:** ngrok (for external access/testing)

## Installation

### Prerequisites

- Python 3.10+
- Npcap (Windows) or libpcap (Linux/Mac) for packet capture
- Administrator/root privileges for real-time monitoring

### Setup

1. **Clone or extract the project**

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize database**
   ```bash
   python run.py init-db
   ```

4. **Create admin user**
   ```bash
   python run.py create-admin
   ```

## Running the Application

### Start the server
```bash
python run.py
```

The application will be available at:
- http://localhost:5000
- http://127.0.0.1:5000

### First-time setup
1. Navigate to http://localhost:5000
2. Click "Register" to create a user account
3. Login with your credentials
4. Access the dashboard for real-time monitoring
5. Upload PCAP files for analysis

## Project Structure

```
project-root/
├── app/                          # Main application package
│   ├── core/                     # Core functionality
│   │   ├── analysis/             # Analysis modules
│   │   ├── capture/              # Scapy packet capture & PCAP analysis
│   │   │   ├── scapy_capture_engine.py    # Real-time packet capture
│   │   │   └── scapy_pcap_analyzer.py     # PCAP file analysis
│   │   └── ml/                   # ML models and predictors
│   │       ├── models/           # Trained model files (.pkl, .json)
│   │       └── multi_model_predictor.py   # Multi-model prediction
│   ├── forms/                    # WTForms for user input
│   │   └── auth_forms.py         # Authentication forms
│   ├── routes/                   # Flask blueprints
│   │   ├── admin.py              # Admin panel routes
│   │   ├── auth.py               # Authentication routes
│   │   ├── dashboard.py          # Dashboard routes
│   │   ├── main.py               # Main routes
│   │   └── pcap.py               # PCAP analysis routes
│   ├── services/                 # Business logic layer
│   │   ├── ml_service.py         # ML prediction service
│   │   ├── monitoring_service.py # Real-time monitoring service
│   │   └── pcap_service.py       # PCAP processing service
│   ├── static/                   # Frontend assets
│   │   ├── css/                  # Stylesheets
│   │   │   ├── dashboard.css     # Dashboard styles
│   │   │   ├── main.css          # Main styles
│   │   │   └── legacy-base.css   # Legacy base styles
│   │   ├── img/                  # Images
│   │   └── js/                   # JavaScript files
│   │       └── dashboard.js      # Dashboard frontend logic
│   ├── templates/                # Jinja2 HTML templates
│   │   ├── admin/                # Admin panel templates
│   │   │   └── panel.html        # Admin panel page
│   │   ├── auth/                 # Authentication templates
│   │   │   ├── login.html        # Login page
│   │   │   ├── register.html     # Registration page
│   │   │   ├── profile.html      # User profile page
│   │   │   ├── change_password.html
│   │   │   ├── forgot_password.html
│   │   │   └── reset_password.html
│   │   ├── dashboard/            # Dashboard templates
│   │   │   └── index.html        # Main dashboard
│   │   ├── errors/               # Error page templates
│   │   │   ├── 403.html          # Forbidden
│   │   │   ├── 404.html          # Not Found
│   │   │   ├── 429.html          # Too Many Requests
│   │   │   └── 500.html          # Internal Server Error
│   │   ├── main/                 # Main page templates
│   │   │   └── about.html        # About page
│   │   ├── pcap/                 # PCAP analysis templates
│   │   │   └── upload.html       # PCAP upload and analysis page
│   │   └── base.html             # Base template
│   ├── utils/                    # Utility modules
│   │   ├── exceptions.py         # Custom exceptions
│   │   ├── logger.py             # Logging configuration
│   │   └── security.py           # Security utilities
│   ├── __init__.py               # Flask app factory
│   ├── config.py                 # Application configuration
│   └── models.py                 # Database models (SQLAlchemy)
├── database/                     # Database layer
│   ├── db_manager.py             # Database management utilities
│   └── nids.db                   # SQLite database file
├── exports/                      # Export directory for reports
├── logs/                         # Application logs
│   └── nids_system.log           # System log file
├── migrations/                   # Database migrations (Alembic)
│   ├── versions/                 # Migration versions
│   ├── alembic.ini               # Alembic configuration
│   └── env.py                    # Migration environment
├── models/                       # ML components (legacy/training)
│   ├── flow_aggregator.py        # Network flow aggregation (51 features)
│   ├── ml_predictor.py           # ML prediction interface
│   ├── packet_capture.py         # Packet capture utilities
│   └── models_file/              # Trained model files
│       ├── xgboost_model.pkl     # XGBoost classifier
│       ├── randomforest_model.pkl # Random Forest classifier
│       ├── knn_model.pkl         # K-Nearest Neighbors classifier
│       ├── scaler.pkl            # Feature scaler
│       ├── features.pkl          # Feature metadata
│       └── backup_*/             # Model backups
├── uploads/                      # Uploaded PCAP files storage
├── config.py                     # Root-level database configuration
├── create_admin.py               # Admin user creation script
├── run.py                        # Application entry point
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

## Key Components

### Real-time Monitoring
- **Service:** `app/services/monitoring_service.py`
- **Engine:** `app/core/capture/scapy_capture_engine.py`
- **Model:** XGBoost only (optimized for speed)
- **Features:** 20 CICIDS2017 network flow features
- **Flow Aggregation:** `models/flow_aggregator.py` - Bidirectional flow tracking with 5-tuple normalization

### PCAP Analysis
- **Service:** `app/services/pcap_service.py`
- **Analyzer:** `app/core/capture/scapy_pcap_analyzer.py`
- **Models:** All 3 models (XGBoost, Random Forest, KNN)
- **Purpose:** Multi-model comparison and offline analysis
- **Predictor:** `app/core/ml/multi_model_predictor.py` - Unified prediction interface

### ML Models
- **XGBoost** - Best accuracy, used for real-time detection
- **Random Forest** - Ensemble learning for comparison and validation
- **K-Nearest Neighbors (KNN)** - Distance-based classification baseline
- **Training Dataset:** CIC-IDS-2017 (binary-class: Normal vs Attack)
- **Model Files:** `app/core/ml/models/` and `models/models_file/`
- **Feature Scaler:** StandardScaler for normalization

### Database & Persistence
- **ORM:** SQLAlchemy with Flask-SQLAlchemy integration
- **Models:** `app/models.py` - User, Alert, Analysis, ActivityLog tables
- **Migrations:** Alembic-based schema versioning in `migrations/`
- **Manager:** `database/db_manager.py` - Database utilities

### Web Interface
- **Routes:** Modular Flask blueprints (main, auth, dashboard, pcap, admin)
- **Templates:** Jinja2 templates with base inheritance
- **Real-time Updates:** Socket.IO for live monitoring dashboard
- **Frontend JS:** `app/static/js/dashboard.js` - Dashboard interactivity

## Usage

### Real-time Monitoring
1. **Login** - Navigate to http://localhost:5000 and login with your credentials
2. **Access Dashboard** - Click on "Dashboard" from the navigation menu
3. **Start Monitoring** - Click "Start Monitoring" button
4. **Select Interface** - Choose your network interface from the dropdown
5. **Live Alerts** - View real-time threat detections with XGBoost predictions
6. **Statistics** - Monitor packet counts, flow statistics, and attack distributions
7. **Stop Monitoring** - Click "Stop Monitoring" to end the session

### PCAP Analysis
1. **Navigate** - Go to "PCAP Analysis" from the menu
2. **Upload** - Click "Choose File" and select a PCAP file (.pcap or .pcapng)
3. **Analyze** - Click "Analyze" to process the file
4. **Multi-Model Results** - View predictions from all 3 models (XGBoost, Random Forest, KNN)
5. **Flow Details** - Review individual flow detections with feature values
6. **Comparison** - Compare model predictions and confidence scores
7. **Export** - Download analysis report as CSV or JSON

### Admin Panel
- **User Management** - View all users, create new accounts, suspend or delete users
- **Activity Logs** - Monitor user actions, login attempts, and system events
- **System Statistics** - View total users, alerts, analyses, and system health
- **Database** - Check database size and performance metrics

### User Profile
- **View Profile** - Access your profile from the navigation menu
- **Change Password** - Update your password securely
- **Activity History** - See your recent login and analysis history
- **Reset Password** - Use "Forgot Password" on login page for password recovery

## Attack Types Detected

- **DDoS** - Distributed Denial of Service
- **DoS** - Denial of Service
- **Port Scan** - Network reconnaissance
- **Brute Force** - Credential attacks
- **Web Attacks** - SQL injection, XSS, etc.
- **Botnet** - Malware command & control
- **Infiltration** - Network penetration

## Notes

### Platform Requirements
- **Windows users:** Requires Npcap (https://npcap.com/) installed with WinPcap compatibility mode
- **Linux users:** Requires libpcap-dev (`sudo apt-get install libpcap-dev`)
- **Mac users:** Requires libpcap (usually pre-installed with Xcode Command Line Tools)

### Permissions
- **Admin/Root privileges:** Required for real-time packet capture on network interfaces
- **File permissions:** Ensure write access to `database/`, `logs/`, `uploads/`, and `exports/` directories

### Model Compatibility
- **scikit-learn versions:** Models trained with 1.6.1, may show warnings on different versions (informational only, works fine)
- **Feature count:** All models expect exactly 20 CICIDS2017 features
- **Model files:** Located in both `app/core/ml/models/` and `models/models_file/` directories

### Performance Notes
- **Real-time monitoring:** Uses XGBoost only for optimal speed
- **PCAP analysis:** Uses all 3 models for comprehensive comparison (slower but more thorough)
- **Flow timeout:** Default 2.0 seconds for flow aggregation
- **Max flows:** Limited to 100,000 active flows to prevent memory issues

### Security Considerations
- **Default setup:** Uses SQLite (not suitable for production with multiple concurrent users)
- **Production deployment:** Consider PostgreSQL/MySQL for better concurrency
- **Password security:** Uses Werkzeug password hashing (pbkdf2:sha256)
- **CSRF protection:** Enabled via Flask-WTF forms

## Updated System Diagrams (Web UI is the endpoint)

The diagrams below have been updated to ensure the Web Application (browser UI) is the user-facing endpoint; the database is storage only.

**Flow Chart**

<img width="466" height="933" alt="Screenshot 2026-02-25 090907" src="https://github.com/user-attachments/assets/4ffe9a05-08d1-4795-a573-9d9987b99050" />

**Use Case**

<img width="1236" height="746" alt="Screenshot 2026-02-25 090837" src="https://github.com/user-attachments/assets/2e16d10b-70d3-466f-97de-9e9f9e1e908b" />

**Architacture Diagram**

<img width="1683" height="832" alt="Screenshot 2026-02-25 090943" src="https://github.com/user-attachments/assets/7ad57f53-015c-412a-8290-37d1923a02ba" />

## Troubleshooting

### Cannot Start Monitoring
**Symptoms:** Real-time monitoring fails to start or crashes immediately

**Solutions:**
- Ensure you're running with **administrator/root privileges**
- Check **Npcap** (Windows) or **libpcap** (Linux/Mac) installation
- Verify network interface name exists: Run `python -c "from scapy.all import get_if_list; print(get_if_list())"`
- On Windows, ensure Npcap is installed with **WinPcap compatibility mode** enabled
- Check firewall/antivirus isn't blocking Scapy packet capture

### Models Not Loading
**Symptoms:** Error messages about missing models or import failures

**Solutions:**
- Verify model files exist in **both** directories:
  - `app/core/ml/models/` (XGBoost_model.pkl, Random_Forest_model.pkl, Logistic_Regression_model.pkl)
  - `models/models_file/` (xgboost_model.pkl, randomforest_model.pkl, knn_model.pkl)
- Check all required packages installed: `pip install -r requirements.txt`
- Verify scikit-learn and xgboost versions are compatible
- If models are corrupt, restore from `models/models_file/backup_*/` directories

### Database Errors
**Symptoms:** SQLAlchemy errors, migration failures, or database locked errors

**Solutions:**
- Initialize database: `python run.py init-db`
- Check file permissions on `database/nids.db`
- If corrupted, delete `database/nids.db` and re-run `init-db`
- For migration issues: `flask db upgrade` or check `migrations/versions/`
- SQLite locked errors: Ensure no other processes are accessing the database

### PCAP Upload Failures
**Symptoms:** Upload errors or analysis hangs

**Solutions:**
- Check PCAP file is valid: Open with Wireshark to verify
- Ensure `uploads/` directory exists and is writable
- Check file size limits in Flask config
- Large PCAP files (>100MB) may take several minutes to process
- Check logs in `logs/nids_system.log` for detailed error messages

### Socket.IO Connection Issues
**Symptoms:** Dashboard doesn't update in real-time, WebSocket errors in browser console

**Solutions:**
- Check Flask-SocketIO is installed: `pip install flask-socketio`
- Verify port 5000 is not blocked by firewall
- Try different browser (Chrome/Firefox recommended)
- Check browser console (F12) for JavaScript errors
- Ensure eventlet or gevent is installed: `pip install eventlet`

### Import Errors
**Symptoms:** `ModuleNotFoundError` or `ImportError` when starting application

**Solutions:**
- Activate virtual environment if using one
- Install all dependencies: `pip install -r requirements.txt`
- Check Python version is 3.10 or higher: `python --version`
- Verify PYTHONPATH includes project root directory

### Performance Issues
**Symptoms:** Slow analysis, high CPU/memory usage, application hangs

**Solutions:**
- Real-time monitoring: Reduce flow timeout (default 2.0s) in `flow_aggregator.py`
- Limit max flows (default 100,000) if memory constrained
- PCAP analysis: Process smaller files or use file splitting
- Database: Consider migrating to PostgreSQL for better performance
- Check system resources: Task Manager (Windows) or `top` (Linux)

### Login/Authentication Problems
**Symptoms:** Cannot login, password reset not working

**Solutions:**
- Create admin user: `python create_admin.py`
- Reset password using "Forgot Password" link on login page
- Check User table in database: `sqlite3 database/nids.db "SELECT * FROM user;"`
- Clear browser cookies and cache
- Verify session secret key in `app/config.py`

## License

Educational project for Final Year Project (FYP) demonstration.

## Author

Developed as a Final Year Project for Network Security and Intrusion Detection.

