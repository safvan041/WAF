"""
Production settings for WAF Project.
Extends base settings with production-specific configurations.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE-THIS-IN-PRODUCTION')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

raw_hosts = os.environ.get("ALLOWED_HOSTS", "")
if raw_hosts:
    ALLOWED_HOSTS = [h.strip() for h in raw_hosts.split(",") if h.strip()]
else:
    # dev-safe default
    ALLOWED_HOSTS = ["*"] if DEBUG else []


# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "waf_project.waf_core",
    "waf_project.waf_engine",
    "waf_project.waf_ml",
    "rest_framework",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # Serve static files
    "waf_project.waf_engine.tenant_middleware.TenantMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "waf_project.waf_engine.middleware.WAFMiddleware"
]

ROOT_URLCONF = "waf_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "waf_project.wsgi.application"

# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

if os.environ.get("DATABASE_URL"):
    DATABASES = {
        "default": dj_database_url.config(
            default=os.environ["DATABASE_URL"],
            conn_max_age=600,
            conn_health_checks=True,
        )
    }
elif os.environ.get("DB_ENGINE", "").lower() == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("DB_NAME", "waf_db"),
            "USER": os.environ.get("DB_USER", "waf_user"),
            "PASSWORD": os.environ.get("DB_PASSWORD", ""),
            "HOST": os.environ.get("DB_HOST", "localhost"),
            "PORT": os.environ.get("DB_PORT", "5432"),
        }
    }
else:
    # default: SQLite (works out of the box on Lightsail)
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

# Cache Configuration (Redis)
if os.environ.get('REDIS_URL'):
    CACHES = {
        "default": {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": os.environ.get('REDIS_URL'),
            "OPTIONS": {
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            }
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# Media files
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "mediafiles"

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Authentication
LOGIN_URL = 'login'
AUTH_USER_MODEL = "waf_core.User"
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'

# GeoIP Configuration
GEOIP_PATH = os.environ.get('GEOIP_PATH', BASE_DIR / 'waf_project' / 'geoip')

# Security Settings
if not DEBUG:
    SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'True').lower() == 'true'
    SESSION_COOKIE_SECURE = SECURE_SSL_REDIRECT
    CSRF_COOKIE_SECURE = SECURE_SSL_REDIRECT
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# CSRF Trusted Origins (needed for Nginx proxy)
raw_csrf_origins = os.environ.get("CSRF_TRUSTED_ORIGINS", "")
if raw_csrf_origins:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in raw_csrf_origins.split(",") if o.strip()]
else:
    CSRF_TRUSTED_ORIGINS = []
    if not SECURE_SSL_REDIRECT and ALLOWED_HOSTS:
         # If no SSL, trust the allowed hosts with http scheme
         CSRF_TRUSTED_ORIGINS = [f"http://{host}" for host in ALLOWED_HOSTS if host != '*']


# CORS Settings (if needed)
raw_cors = os.environ.get("CORS_ALLOWED_ORIGINS", "")
if raw_cors:
    CORS_ALLOWED_ORIGINS = [o.strip() for o in raw_cors.split(",") if o.strip()]
else:
    CORS_ALLOWED_ORIGINS = []


# Logging Configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'level': os.environ.get('LOG_LEVEL', 'INFO'),
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': os.environ.get('LOG_LEVEL', 'INFO'),
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': os.environ.get('LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
        'waf_engine': {
            'handlers': ['console'],
            'level': os.environ.get('LOG_LEVEL', 'INFO'),
            'propagate': False,
        },
    },
}

# Sentry Configuration (optional)
if os.environ.get('SENTRY_DSN'):
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration
    
    sentry_sdk.init(
        dsn=os.environ.get('SENTRY_DSN'),
        integrations=[DjangoIntegration()],
        traces_sample_rate=0.1,
        send_default_pii=False,
        environment=os.environ.get('ENVIRONMENT', 'production'),
    )

# WAF Machine Learning Configuration
WAF_ML_ENABLED = os.environ.get('WAF_ML_ENABLED', 'True').lower() == 'true'
WAF_ML_ANOMALY_THRESHOLD = float(os.environ.get('WAF_ML_ANOMALY_THRESHOLD', '0.8'))
WAF_ML_AUTO_APPROVE_THRESHOLD = float(os.environ.get('WAF_ML_AUTO_APPROVE_THRESHOLD', '0.95'))
WAF_ML_TRAINING_WINDOW_DAYS = int(os.environ.get('WAF_ML_TRAINING_WINDOW_DAYS', '7'))
WAF_ML_MIN_SAMPLES_FOR_TRAINING = int(os.environ.get('WAF_ML_MIN_SAMPLES_FOR_TRAINING', '100'))
WAF_ML_FEATURE_EXTRACTION_ENABLED = os.environ.get('WAF_ML_FEATURE_EXTRACTION_ENABLED', 'True').lower() == 'true'
WAF_ML_PATTERN_AGGREGATION_MINUTES = int(os.environ.get('WAF_ML_PATTERN_AGGREGATION_MINUTES', '60'))
WAF_ML_ENABLE_FALLBACK_RULES = os.environ.get('WAF_ML_ENABLE_FALLBACK_RULES', 'False').lower() == 'true'
