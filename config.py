# app/config.py
# All detection thresholds and protection settings. Time values are in seconds.

# Brute force: repeated failed logins on one account
BRUTE_FORCE_MAX_FAILS = 5
BRUTE_FORCE_WINDOW = 60
BRUTE_FORCE_CRITICAL_FAILS = 15

# Credential stuffing: one IP trying many different accounts
STUFFING_MIN_ACCOUNTS = 10
STUFFING_WINDOW = 120

# Email spam
EMAIL_MAX_PER_MINUTE = 30
EMAIL_SPIKE_MULTIPLIER = 10

# API abuse: too many requests from one IP
API_MAX_PER_MINUTE = 100

# Behavior change: activity far above the user's own normal
BASELINE_MIN_EVENTS = 5
BEHAVIOR_CHANGE_MULTIPLIER = 8

# Temporary protection (expires automatically)
RATE_LIMIT_SECONDS = 60
BLOCK_SECONDS = 300
RESTRICT_SECONDS = 300

# Severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
