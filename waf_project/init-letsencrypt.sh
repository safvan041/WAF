#!/bin/bash

# init-letsencrypt.sh - Initialize Let's Encrypt certificates for Docker Compose setup
# This script handles the chicken-and-egg problem of Nginx needing certs that don't exist yet

set -e

# Detect docker compose command (v2 uses 'docker compose', v1 uses 'docker-compose')
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    echo 'Error: Neither docker-compose nor docker compose is available.' >&2
    exit 1
fi

echo "Using: $DOCKER_COMPOSE"

# Configuration
domains=(demo.waf-app.site)
rsa_key_size=4096
data_path="./certbot"
email="safvanbakkar041@gmail.com"
staging=1   # 1 = use Let's Encrypt STAGING (test), 0 = PRODUCTION

echo "### Checking for existing certificates..."
if [ -d "$data_path/conf/live/${domains[0]}" ]; then
  read -p "Existing certificates found. Continue and replace? (y/N) " decision
  if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
    echo "Aborted."
    exit 0
  fi
fi

echo "### Creating temporary Nginx config (HTTP only)..."
cat > nginx/nginx-temp.conf << 'EOF'
upstream waf_app {
    server web:8000;
}

server {
    listen 80;
    server_name demo.waf-app.site localhost 127.0.0.1;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://waf_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

# Backup original config once
if [ ! -f nginx/nginx-ssl.conf ]; then
    cp nginx/nginx.conf nginx/nginx-ssl.conf
fi

# Use temporary config
cp nginx/nginx-temp.conf nginx/nginx.conf

echo "### Starting services with HTTP-only config..."
$DOCKER_COMPOSE down
$DOCKER_COMPOSE up -d db redis web nginx

echo "### Waiting for services to be ready..."
sleep 30

echo "### Requesting Let's Encrypt certificate for ${domains[*]}..."

# Build domain arguments
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

# Email argument
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *)  email_arg="--email $email" ;;
esac

# Staging / production
if [ "$staging" != "0" ]; then
    staging_arg="--staging"
    echo "### Using Let's Encrypt STAGING environment (for testing)"
else
    staging_arg=""
    echo "### Using Let's Encrypt PRODUCTION environment"
fi

# IMPORTANT: override entrypoint so we call certbot directly, not the renew-wrapper
$DOCKER_COMPOSE run --rm \
  --entrypoint certbot \
  certbot \
  certonly --webroot \
  -w /var/www/certbot \
  $staging_arg \
  $email_arg \
  $domain_args \
  --rsa-key-size $rsa_key_size \
  --agree-tos \
  --non-interactive \
  --force-renewal

echo "### Certificate obtained successfully!"

echo "### Restoring SSL-enabled Nginx config..."
cp nginx/nginx-ssl.conf nginx/nginx.conf

echo "### Restarting Nginx with SSL..."
$DOCKER_COMPOSE restart nginx

echo "### Starting Certbot service for auto-renewal..."
$DOCKER_COMPOSE up -d certbot

echo ""
echo "✅ SUCCESS! Your site should now be accessible via HTTPS"
echo ""
if [ "$staging" != "0" ]; then
    echo "⚠️  NOTE: You used STAGING mode. The certificate will show a browser warning."
    echo "   To get a trusted certificate, set staging=0 and run this script again."
fi
echo ""
echo "Test your site: https://${domains[0]}"
