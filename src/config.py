import os 
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join("BASE_DIR", ".env"))

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_DATABASE"),
}

RISK_THRESHOLD = 70

EVENTS_WEIGHT = {

    # SSH Events
    "accepted_login": 0,
    "authentication_failure": 10,
    "failed_login": 10,
    "invalid_user": 15,

    # Web Access Events
    "web_cmd_injection": 90,
    "web_sql_injection": 80,
    "web_path_traversal": 75,
    "web_xss_attempt": 65,
    "web_sensitive_probe": 50,
    "web_auth_failure": 25,
    "web_server_error": 20,
    "web_account_endpoint": 10,
    "web_not_found": 5,
    "web_health_check": 0,
    "web_access": 0,

    # UFW Firewall Events
    "ufw_block_critical_api": 60,
    "ufw_block_telnet_iot": 45,
    "ufw_block_database": 40,
    "ufw_block_remote_admin": 30,
    "ufw_block_voip_ldap": 25,
    "ufw_block_traceroute": 15,
    "ufw_block": 10,
    "ufw_block_https_noise": 2,
    "ufw_block_multicast": 0,
    "ufw_allow": 0,
    
    # Fallback
    "unclassified": 0   
}

HIGH_RISK_AGENTS = ["sqlmap", "nikto", "nmap", "curl", "wget", "python", "dirbuster", "gobuster", "hydra"]
HIGH_RISK_AGENTS_BONUS = 40

BOT_AGENTS = ["bot", "crawler", "spider", "ahrefs"]
BOT_AGENTS_BONUS = 0

# High Risk User
HIGH_RISK_USER = {"root", "admin", "mysql", "oracle", "ubuntu", "test", "guest", "postgres"}
HIGH_RISK_USER_BONUS = 25

# Brute-force repetition settings
BRUTE_FORCE_LIMIT = 5
BRUTE_FORCE_BONUS = 50

# OFF Hours
OFF_HOURS_START = 22 
OFF_HOURS_END = 6
OFF_HOURS_BONUS = 25