# AWS Lightsail Deployment Guide

## Overview
Deploy your WAF Django application to AWS Lightsail using containers. Lightsail is a simplified AWS service that's perfect for small to medium applications with predictable pricing.

## Prerequisites
- AWS Account
- AWS CLI installed and configured
- Docker installed locally
- Your application tested locally (✅ completed)

## Deployment Options

### Option 1: Lightsail Container Service (Recommended)
Simple, managed container deployment with built-in load balancing.

### Option 2: Lightsail Instance with Docker
More control, requires manual setup and maintenance.

---

## Option 1: Lightsail Container Service (Recommended)

### Step 1: Create Lightsail Container Service

```bash
# Create a container service (nano = $7/month, micro = $10/month, small = $40/month)
aws lightsail create-container-service \
    --service-name waf-app \
    --power small \
    --scale 1 \
    --region us-east-1
```

**Power options**:
- `nano`: 0.25 vCPU, 512 MB RAM - $7/month
- `micro`: 0.5 vCPU, 1 GB RAM - $10/month
- `small`: 1 vCPU, 2 GB RAM - $40/month
- `medium`: 2 vCPU, 4 GB RAM - $80/month

### Step 2: Push Docker Image to Lightsail

```bash
# Build your Docker image
docker build -t waf-app:latest .

# Push to Lightsail (Lightsail will provide push commands)
aws lightsail push-container-image \
    --service-name waf-app \
    --label waf-app-latest \
    --image waf-app:latest \
    --region us-east-1
```

**Note the image name** from the output (e.g., `:waf-app.waf-app-latest.1`)

### Step 3: Create Deployment Configuration

Create a file `lightsail-deployment.json`:

```json
{
  "serviceName": "waf-app",
  "containers": {
    "waf-app": {
      "image": ":waf-app.waf-app-latest.1",
      "ports": {
        "8000": "HTTP"
      },
      "environment": {
        "DJANGO_SETTINGS_MODULE": "waf_project.settings_production",
        "DEBUG": "False",
        "SECRET_KEY": "your-secret-key-here-change-this",
        "ALLOWED_HOSTS": "*.awsapprunner.com,your-domain.com",
        "DB_ENGINE": "sqlite"
      }
    }
  },
  "publicEndpoint": {
    "containerName": "waf-app",
    "containerPort": 8000,
    "healthCheck": {
      "path": "/health/",
      "intervalSeconds": 30,
      "timeoutSeconds": 5,
      "successCodes": "200",
      "healthyThreshold": 2,
      "unhealthyThreshold": 2
    }
  }
}
```

### Step 4: Deploy the Container

```bash
aws lightsail create-container-service-deployment \
    --cli-input-json file://lightsail-deployment.json \
    --region us-east-1
```

### Step 5: Check Deployment Status

```bash
# Check service status
aws lightsail get-container-services \
    --service-name waf-app \
    --region us-east-1

# Get the public URL
aws lightsail get-container-services \
    --service-name waf-app \
    --query 'containerServices[0].url' \
    --output text \
    --region us-east-1
```

### Step 6: Run Database Migrations (if using SQLite)

Since you're using SQLite by default (based on your settings changes), migrations will run automatically via the entrypoint script when the container starts.

### Step 7: Create Superuser

You'll need to access the container to create a superuser. Unfortunately, Lightsail containers don't support direct shell access, so you have two options:

**Option A**: Set environment variables to auto-create superuser:
```json
"CREATE_SUPERUSER": "true",
"DJANGO_SUPERUSER_USERNAME": "admin",
"DJANGO_SUPERUSER_EMAIL": "admin@example.com",
"DJANGO_SUPERUSER_PASSWORD": "changeme123"
```

**Option B**: Use a management command endpoint (create a custom Django command)

---

## Option 2: Lightsail Instance with Docker

### Step 1: Create Lightsail Instance

```bash
# Create a Linux instance (Ubuntu 22.04)
aws lightsail create-instances \
    --instance-names waf-server \
    --availability-zone us-east-1a \
    --blueprint-id ubuntu_22_04 \
    --bundle-id medium_2_0 \
    --region us-east-1
```

**Bundle options**:
- `micro_2_0`: 1 GB RAM, 1 vCPU - $5/month
- `small_2_0`: 2 GB RAM, 1 vCPU - $10/month
- `medium_2_0`: 4 GB RAM, 2 vCPU - $20/month
- `large_2_0`: 8 GB RAM, 2 vCPU - $40/month

### Step 2: Open Firewall Ports

```bash
aws lightsail open-instance-public-ports \
    --instance-name waf-server \
    --port-info fromPort=80,toPort=80,protocol=TCP \
    --region us-east-1

aws lightsail open-instance-public-ports \
    --instance-name waf-server \
    --port-info fromPort=443,toPort=443,protocol=TCP \
    --region us-east-1

aws lightsail open-instance-public-ports \
    --instance-name waf-server \
    --port-info fromPort=8000,toPort=8000,protocol=TCP \
    --region us-east-1
```

### Step 3: Get Instance IP and SSH Key

```bash
# Get public IP
aws lightsail get-instance \
    --instance-name waf-server \
    --query 'instance.publicIpAddress' \
    --output text \
    --region us-east-1

# Download SSH key
aws lightsail download-default-key-pair \
    --region us-east-1 \
    --output text \
    --query 'privateKeyBase64' | base64 --decode > lightsail-key.pem

chmod 400 lightsail-key.pem
```

### Step 4: SSH into Instance and Setup

```bash
ssh -i lightsail-key.pem ubuntu@YOUR_INSTANCE_IP
```

Once connected, run:

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Logout and login again for docker group to take effect
exit
```

### Step 5: Deploy Application

SSH back in and:

```bash
# Clone or upload your application
# For this example, we'll create the files manually

# Create app directory
mkdir -p ~/waf-app
cd ~/waf-app

# Upload your files (use scp from your local machine)
```

From your **local machine**:

```bash
# Upload application files
scp -i lightsail-key.pem -r c:\Users\DELL\WAF\waf_project/* ubuntu@YOUR_INSTANCE_IP:~/waf-app/

# Or create a tar and upload
cd c:\Users\DELL\WAF\waf_project
tar -czf waf-app.tar.gz .
scp -i lightsail-key.pem waf-app.tar.gz ubuntu@YOUR_INSTANCE_IP:~/
```

Back on the **Lightsail instance**:

```bash
cd ~/waf-app

# Extract if you uploaded tar
# tar -xzf ~/waf-app.tar.gz

# Create production .env file
cat > .env << 'EOF'
DJANGO_SETTINGS_MODULE=waf_project.settings_production
DEBUG=False
SECRET_KEY=your-secret-key-change-this-to-something-random
ALLOWED_HOSTS=YOUR_INSTANCE_IP,your-domain.com
DB_ENGINE=sqlite
EOF

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f
```

### Step 6: Setup Nginx Reverse Proxy (Optional but Recommended)

```bash
# Install Nginx
sudo apt install nginx -y

# Create Nginx config
sudo nano /etc/nginx/sites-available/waf-app
```

Add this configuration:

```nginx
server {
    listen 80;
    server_name YOUR_INSTANCE_IP your-domain.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /home/ubuntu/waf-app/staticfiles/;
    }

    location /media/ {
        alias /home/ubuntu/waf-app/mediafiles/;
    }
}
```

Enable the site:

```bash
sudo ln -s /etc/nginx/sites-available/waf-app /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## Adding a Database (Optional)

### Option A: Lightsail Managed Database

```bash
# Create a PostgreSQL database
aws lightsail create-relational-database \
    --relational-database-name waf-db \
    --relational-database-blueprint-id postgres_12 \
    --relational-database-bundle-id micro_2_0 \
    --master-database-name wafdb \
    --master-username wafadmin \
    --master-user-password YourSecurePassword123 \
    --region us-east-1
```

**Pricing**: Starts at $15/month for micro instance

Then update your `.env` or `lightsail-deployment.json`:

```bash
DATABASE_URL=postgresql://wafadmin:YourSecurePassword123@your-db-endpoint:5432/wafdb
```

### Option B: Keep Using SQLite

Your current setup already defaults to SQLite, which is fine for small to medium traffic. No additional database needed!

---

## Custom Domain Setup

### Step 1: Create Static IP (for Instance deployment)

```bash
aws lightsail allocate-static-ip \
    --static-ip-name waf-static-ip \
    --region us-east-1

aws lightsail attach-static-ip \
    --static-ip-name waf-static-ip \
    --instance-name waf-server \
    --region us-east-1
```

### Step 2: Create DNS Zone

```bash
aws lightsail create-domain \
    --domain-name your-domain.com \
    --region us-east-1
```

### Step 3: Add DNS Records

Point your domain to the Lightsail service URL or static IP in your domain registrar's DNS settings.

---

## Monitoring and Logs

### Container Service Logs

```bash
aws lightsail get-container-log \
    --service-name waf-app \
    --container-name waf-app \
    --region us-east-1
```

### Instance Logs

```bash
# SSH into instance
ssh -i lightsail-key.pem ubuntu@YOUR_INSTANCE_IP

# View Docker logs
docker-compose logs -f web
```

---

## Cost Comparison

| Service | Configuration | Monthly Cost |
|---------|--------------|--------------|
| Container Service (nano) | 0.25 vCPU, 512 MB | $7 |
| Container Service (micro) | 0.5 vCPU, 1 GB | $10 |
| Container Service (small) | 1 vCPU, 2 GB | $40 |
| Instance (micro) | 1 GB RAM, 1 vCPU | $5 |
| Instance (small) | 2 GB RAM, 1 vCPU | $10 |
| Instance (medium) | 4 GB RAM, 2 vCPU | $20 |
| Managed DB (micro) | PostgreSQL | $15 |

**Recommendation**: Start with Container Service (micro) at $10/month with SQLite, or Instance (small) at $10/month.

---

## Quick Start Commands

### For Container Service:
```bash
# 1. Build and push
docker build -t waf-app:latest .
aws lightsail create-container-service --service-name waf-app --power micro --scale 1 --region us-east-1
aws lightsail push-container-image --service-name waf-app --label waf-app-latest --image waf-app:latest --region us-east-1

# 2. Deploy (after creating lightsail-deployment.json)
aws lightsail create-container-service-deployment --cli-input-json file://lightsail-deployment.json --region us-east-1

# 3. Get URL
aws lightsail get-container-services --service-name waf-app --query 'containerServices[0].url' --output text --region us-east-1
```

### For Instance:
```bash
# 1. Create instance
aws lightsail create-instances --instance-names waf-server --availability-zone us-east-1a --blueprint-id ubuntu_22_04 --bundle-id small_2_0 --region us-east-1

# 2. Get IP and SSH key
aws lightsail get-instance --instance-name waf-server --query 'instance.publicIpAddress' --output text --region us-east-1
aws lightsail download-default-key-pair --region us-east-1 --output text --query 'privateKeyBase64' | base64 --decode > lightsail-key.pem

# 3. Upload and deploy (see Step 5 above)
```

---

## Troubleshooting

### Container won't start
- Check logs: `aws lightsail get-container-log --service-name waf-app --container-name waf-app`
- Verify environment variables in deployment JSON
- Ensure health check path `/health/` is accessible

### Can't access application
- Check firewall ports are open
- Verify ALLOWED_HOSTS includes your domain/IP
- Check container/service status

### Database connection issues
- Verify DATABASE_URL is correct
- Check database security settings allow connections
- Ensure database is in same region

---

## Next Steps

1. **Choose your deployment option** (Container Service recommended for simplicity)
2. **Generate a secure SECRET_KEY**: `python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'`
3. **Update ALLOWED_HOSTS** with your actual domain/IP
4. **Deploy using the commands above**
5. **Test your application** at the provided URL
6. **Set up custom domain** (optional)
7. **Enable HTTPS** with Let's Encrypt (for instance deployment)

Good luck with your deployment! 🚀
