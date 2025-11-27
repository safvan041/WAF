# SSL Setup with Let's Encrypt

This guide explains how to set up SSL certificates using Let's Encrypt for the WAF application.

## Prerequisites

Before running the setup script, ensure:

1. **Domain DNS is configured**: `demo.waf-app.site` must point to your server's public IP address
2. **Firewall ports are open**: Ports 80 and 443 must be accessible from the internet
3. **Docker is running**: Docker and Docker Compose must be installed and running
4. **Email is configured**: Update the email in `init-letsencrypt.sh` (line 14)

## Initial Setup

### 1. Configure the Script

Edit `init-letsencrypt.sh` and update:
- `domains`: Your domain name(s)
- `email`: Your email address for Let's Encrypt notifications
- `staging`: Set to `1` for testing, `0` for production

### 2. Run the Initialization Script

On your production server (Linux/Mac):

```bash
chmod +x init-letsencrypt.sh
./init-letsencrypt.sh
```

On Windows (using Git Bash or WSL):

```bash
bash init-letsencrypt.sh
```

### 3. What the Script Does

1. Creates dummy SSL certificates
2. Starts Nginx with dummy certificates
3. Deletes dummy certificates
4. Requests real certificates from Let's Encrypt
5. Reloads Nginx with real certificates

## Testing with Staging

**IMPORTANT**: Always test with staging first to avoid hitting Let's Encrypt rate limits.

1. Set `staging=1` in `init-letsencrypt.sh`
2. Run the script
3. Verify the setup works (browser will show staging certificate warning)
4. Set `staging=0` and run again for production certificates

## Certificate Renewal

Certificates are automatically renewed by the Certbot container, which:
- Checks for renewal every 12 hours
- Renews certificates that expire in less than 30 days
- Nginx reloads every 6 hours to pick up renewed certificates

### Manual Renewal

To manually renew certificates:

```bash
docker-compose run --rm certbot certbot renew
docker-compose exec nginx nginx -s reload
```

### Test Renewal

To test the renewal process without actually renewing:

```bash
docker-compose run --rm certbot certbot renew --dry-run
```

## Troubleshooting

### Certificate Request Fails

**Issue**: Certbot cannot validate domain ownership

**Solutions**:
1. Verify DNS points to your server: `nslookup demo.waf-app.site`
2. Check port 80 is accessible: `curl http://demo.waf-app.site/.well-known/acme-challenge/test`
3. Check Nginx logs: `docker-compose logs nginx`
4. Check Certbot logs: `docker-compose logs certbot`

### Nginx Fails to Start

**Issue**: Nginx cannot find certificate files

**Solutions**:
1. Ensure dummy certificates were created
2. Check volume mounts: `docker volume ls`
3. Verify certificate paths in `nginx.conf`

### Rate Limit Errors

**Issue**: "too many certificates already issued"

**Solutions**:
1. Wait 7 days for the limit to reset
2. Use staging environment for testing
3. Check current limits: https://letsencrypt.org/docs/rate-limits/

## Production Deployment

1. **Push code to repository**:
   ```bash
   git add .
   git commit -m "Add Let's Encrypt SSL support"
   git push
   ```

2. **On production server**:
   ```bash
   git pull
   chmod +x init-letsencrypt.sh
   ./init-letsencrypt.sh
   ```

3. **Verify HTTPS**:
   - Visit `https://demo.waf-app.site`
   - Check certificate is valid and trusted
   - Verify HTTP redirects to HTTPS

## Certificate Locations

- **Certificates**: `/etc/letsencrypt/live/demo.waf-app.site/`
- **Private Key**: `privkey.pem`
- **Certificate Chain**: `fullchain.pem`
- **Certificate Only**: `cert.pem`
- **Chain Only**: `chain.pem`

## Security Notes

- Never commit certificate files to Git (already in `.gitignore`)
- Keep your private key secure
- Use strong email password for Let's Encrypt account
- Monitor certificate expiration dates
- Enable HSTS headers (already configured)
