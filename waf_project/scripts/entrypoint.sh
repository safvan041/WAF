#!/bin/bash
set -e

echo "Starting WAF Application..."

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
while ! pg_isready -h "${DB_HOST:-db}" -p "${DB_PORT:-5432}" -U "${DB_USER:-waf_user}" > /dev/null 2>&1; do
    echo "PostgreSQL is unavailable - sleeping"
    sleep 2
done
echo "PostgreSQL is up and running!"

# Wait for Redis to be ready (if configured)
if [ -n "$REDIS_URL" ] || [ -n "$REDIS_HOST" ]; then
    echo "Waiting for Redis..."
    REDIS_HOST_VAR="${REDIS_HOST:-redis}"
    REDIS_PORT_VAR="${REDIS_PORT:-6379}"
    
    until redis-cli -h "$REDIS_HOST_VAR" -p "$REDIS_PORT_VAR" ping > /dev/null 2>&1; do
        echo "Redis is unavailable - sleeping"
        sleep 2
    done
    echo "Redis is up and running!"
fi

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput --clear

# Create superuser if it doesn't exist (optional - for initial setup)
if [ "$CREATE_SUPERUSER" = "true" ]; then
    echo "Creating superuser..."
    python manage.py shell << END
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='${DJANGO_SUPERUSER_USERNAME:-admin}').exists():
    User.objects.create_superuser(
        username='${DJANGO_SUPERUSER_USERNAME:-admin}',
        email='${DJANGO_SUPERUSER_EMAIL:-admin@example.com}',
        password='${DJANGO_SUPERUSER_PASSWORD:-admin}'
    )
    print('Superuser created successfully')
else:
    print('Superuser already exists')
END
fi

echo "Starting application server..."
# Execute the main command (passed as arguments to this script)
exec "$@"
