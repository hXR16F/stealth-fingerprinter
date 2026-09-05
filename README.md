# Stealth Fingerprinter (SF)

A sophisticated URL-based tracking and fingerprinting system with bot detection, endpoint management, and advanced obfuscation capabilities.

---

## Overview

Stealth Fingerprinter (SF) is a web-based platform that enables users to create trackable URLs with intelligent visitor differentiation. The system automatically distinguishes between human visitors and automated bots, serving tailored responses while collecting comprehensive fingerprint data for analytics purposes.

---

## Features

### Core Functionality

- **Tracking Endpoints:** Generate unique URLs that log every visit with detailed metadata
- **Bot Detection:** Automatically identifies and categorizes bot traffic using user-agent pattern matching
- **Visitor Fingerprinting:** Collects browser, screen, WebGL, audio, and font fingerprints via JavaScript
- **Dual Behavior System:** Configurable responses for bots and real users

### Bot Behavior Options

| Behavior | Description |
|----------|-------------|
| Custom Meta Tags | Display user-defined HTML meta tags to bots |
| Display Image | Show an image to bots (upload or URL) |
| Mimic Website | Fetch and display meta tags from any target website |
| Redirect | Forward bots to a custom URL or about:blank |
| Do Nothing | Treat bots as normal visitors and show standard response |

### User Behavior Options

| Behavior | Description |
|----------|-------------|
| Display Image | Show an image to human visitors |
| Redirect | Forward visitors to a custom URL or about:blank |
| Alert | Display a JavaScript alert with custom message |

### Tracking Aliases

Create multiple endpoints with identical behavior but different tracking aliases:
- Generate unique endpoints for different campaigns or partners
- Identify traffic sources in the dashboard
- Example: `campaign1, friend, partner`

### Obfuscation Features

#### URL Obfuscation
- **Hostname Percent-Hex Encoding**: Encode characters in the hostname using percent-hex notation
- **Dot Percent-Hex Encoding**: Encode dots separating hostname labels as `%2e`
- **Homoglyph Replacement**: Replace protocol characters with visually identical Unicode lookalikes to bypass automated filters

#### URL Spoofing
- **Redirect-Based**: Wrap your URL in known redirectors (Google, Facebook)
- **Userinfo-Based**: Abuse userinfo component to associate with trusted domains

### Dashboard Capabilities

- **Visit Statistics**: Real-time counters for total, bot, and human visits
- **Endpoint Management**: Create, view, and delete tracking endpoints
- **Detailed Visit Logs**:
  - IP address with external lookup integration
  - Browser, operating system, and device detection
  - Full request headers
  - Complete JavaScript fingerprinting data
  - Timestamp with UTC timezone
- **Advanced Filtering**:
  - Regular expression filtering
  - Hide bots toggle
  - Pagination with adjustable results per page
- **Bulk Operations**: Delete multiple visits simultaneously

---

## Installation

### Prerequisites

- Python 3.11 or higher
- Docker (Optional)

### Local Installation

1. Clone the repository:
```
git clone https://github.com/hXR16F/stealth-fingerprinter
cd stealth-fingerprinter
```

2. Create and activate a virtual environment:
```
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Run:
For development and testing purposes, use the built-in Flask development server:
```
python app.py
```

For production deployments, use Gunicorn, a production-grade WSGI HTTP server:
```
gunicorn --bind 0.0.0.0:5000 app:app
```


### Docker Installation

### Docker Installation

1. Build the Docker image:
```
docker build -t stealth-fingerprinter .
```

2. Run the container:
```
docker run -d --name sf-app -p 5000:5000 -e SECRET_KEY="your-secret-key-here" stealth-fingerprinter
```

Or with a `.env` file:
```
docker run -d --name sf-app -p 5000:5000 --env-file .env stealth-fingerprinter
```

---

## Usage

### Creating a License

```
# Local installation
python app.py create-license "username"

# Docker
docker exec -it sf-app python app.py create-license "username"
```

### User Management

```
# List all users
python app.py list-users

# Disable a user
python app.py disable-user "username"

# Enable a user
python app.py enable-user "username"
```

### Using the Dashboard

1. Access the application at `http://localhost:5000`
2. Log in with your license key
3. Create endpoints with custom behavior configurations
4. Copy the generated URLs for distribution
5. Monitor visits and fingerprint data in real-time

### Generating Tracking URLs

1. Select bot and user behaviors
2. Configure behavior-specific parameters (images, URLs, meta tags)
3. Enter tracking aliases (comma-separated) to create multiple endpoints
4. Click "Create endpoints"
5. Copy the generated URLs from the endpoints table

### Obfuscating URLs

1. Configure obfuscation settings in the Obfuscation section
2. Click "Copy URL" or "Copy As" on any endpoint
3. The URL will be automatically obfuscated according to your settings

---

## Architecture

### Technology Stack

- **Backend**: Flask (Python 3.11)
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Containerization**: Docker
- **Server**: Gunicorn (production) / Flask development server

### Data Storage

- `data/db.sqlite3`: SQLite database for users, visits, and fingerprints
- `data/endpoints.json`: JSON file for endpoint configurations
- `data/uploads/`: Uploaded image files

### Key Components

- **Authentication**: License key-based authentication with session management
- **Endpoint System**: JSON-based storage with unique token generation
- **Visit Logging**: Comprehensive request metadata capture
- **Fingerprinting**: Client-side JavaScript data collection
- **Bot Detection**: User-agent pattern matching with extensible definitions

---

## License

This project is licensed under the GPL-3.0 License.
