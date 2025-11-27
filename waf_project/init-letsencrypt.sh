#!/bin/bash

# init-letsencrypt.sh - Initialize Let's Encrypt certificates for Docker Compose setup
# This script creates dummy certificates, starts nginx, and then requests real certificates

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
email="safvanbakkar041@gmail.com" # Adding a valid address is strongly recommended
staging=1 # Set to 1 if you're testing your setup to avoid hitting request limits

echo "### Preparing directories ..."
mkdir -p "$data_path/conf/live/$domains"

if [ -d "$data_path/conf/live/$domains" ]; then
  read -p "Existing data found for $domains. Continue and replace existing certificate? (y/N) " decision
  if [ "$decision" != "Y" ] && [ "$decision" != "y" ]; then
    exit
  fi
fi

echo "### Creating dummy certificate for $domains ..."
path="/etc/letsencrypt/live/$domains"
mkdir -p "$data_path/conf/live/$domains"
$DOCKER_COMPOSE run --rm --entrypoint "\
  openssl req -x509 -nodes -newkey rsa:$rsa_key_size -days 1\
    -keyout '$path/privkey.pem' \
    -out '$path/fullchain.pem' \
    -subj '/CN=localhost'" certbot
echo

echo "### Starting nginx ..."
$DOCKER_COMPOSE up --force-recreate -d nginx
echo

echo "### Deleting dummy certificate for $domains ..."
$DOCKER_COMPOSE run --rm --entrypoint "\
  rm -Rf /etc/letsencrypt/live/$domains && \
  rm -Rf /etc/letsencrypt/archive/$domains && \
  rm -Rf /etc/letsencrypt/renewal/$domains.conf" certbot
echo

echo "### Requesting Let's Encrypt certificate for $domains ..."
# Join $domains to -d args
domain_args=""
for domain in "${domains[@]}"; do
  domain_args="$domain_args -d $domain"
done

# Select appropriate email arg
case "$email" in
  "") email_arg="--register-unsafely-without-email" ;;
  *) email_arg="--email $email" ;;
esac

# Enable staging mode if needed
if [ $staging != "0" ]; then staging_arg="--staging"; fi

$DOCKER_COMPOSE run --rm --entrypoint "\
  certbot certonly --webroot -w /var/www/certbot \
    $staging_arg \
    $email_arg \
    $domain_args \
    --rsa-key-size $rsa_key_size \
    --agree-tos \
    --force-renewal" certbot
echo

echo "### Reloading nginx ..."
$DOCKER_COMPOSE exec nginx nginx -s reload
