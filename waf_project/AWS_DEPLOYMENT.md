# AWS Deployment Guide for WAF Application

This guide provides step-by-step instructions for deploying the WAF Django application to AWS using Docker and ECS Fargate.

## Prerequisites

- AWS Account with appropriate permissions
- AWS CLI installed and configured
- Docker installed locally
- Domain name (optional, for custom domain)
- GeoLite2-Country.mmdb file from MaxMind

## Architecture Overview

The deployment uses the following AWS services:

- **Amazon ECS Fargate**: Container orchestration
- **Amazon RDS PostgreSQL**: Database
- **Amazon ElastiCache Redis**: Caching and rate limiting
- **Application Load Balancer**: Traffic distribution
- **Amazon ECR**: Docker image registry
- **AWS Secrets Manager**: Secure credential storage
- **Amazon CloudWatch**: Logging and monitoring

## Deployment Steps

### 1. Initial AWS Setup

#### 1.1 Create ECR Repository

```bash
aws ecr create-repository \
    --repository-name waf-app \
    --region us-east-1
```

#### 1.2 Store Secrets in AWS Secrets Manager

```bash
# Django Secret Key
aws secretsmanager create-secret \
    --name waf/django-secret-key \
    --secret-string "your-generated-secret-key-here" \
    --region us-east-1

# Database credentials
aws secretsmanager create-secret \
    --name waf/db-username \
    --secret-string "wafadmin" \
    --region us-east-1

aws secretsmanager create-secret \
    --name waf/db-password \
    --secret-string "your-secure-password" \
    --region us-east-1

# Allowed hosts
aws secretsmanager create-secret \
    --name waf/allowed-hosts \
    --secret-string "your-domain.com,your-alb-dns.amazonaws.com" \
    --region us-east-1
```

### 2. Deploy Infrastructure with CloudFormation

#### 2.1 Update CloudFormation Template

Edit `aws/cloudformation-template.yml` and update:
- `ContainerImage` parameter with your ECR repository URL
- Any other parameters as needed

#### 2.2 Deploy the Stack

```bash
aws cloudformation create-stack \
    --stack-name waf-prod-stack \
    --template-body file://aws/cloudformation-template.yml \
    --parameters \
        ParameterKey=EnvironmentName,ParameterValue=waf-prod \
        ParameterKey=DBPassword,ParameterValue=YourSecurePassword123 \
        ParameterKey=ContainerImage,ParameterValue=YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/waf-app:latest \
    --capabilities CAPABILITY_IAM \
    --region us-east-1
```

#### 2.3 Wait for Stack Creation

```bash
aws cloudformation wait stack-create-complete \
    --stack-name waf-prod-stack \
    --region us-east-1
```

This will take approximately 10-15 minutes.

#### 2.4 Get Stack Outputs

```bash
aws cloudformation describe-stacks \
    --stack-name waf-prod-stack \
    --region us-east-1 \
    --query 'Stacks[0].Outputs'
```

Note the ALB URL, RDS endpoint, and Redis endpoint.

### 3. Build and Deploy Application

#### 3.1 Set Environment Variables

```bash
export AWS_ACCOUNT_ID=123456789012
export AWS_REGION=us-east-1
export ECR_REPOSITORY=waf-app
export ECS_CLUSTER=waf-prod-cluster
export ECS_SERVICE=waf-prod-service
export IMAGE_TAG=latest
```

#### 3.2 Run Deployment Script

```bash
chmod +x deploy.sh
./deploy.sh
```

Or manually:

```bash
# Build image
docker build -t waf-app:latest .

# Login to ECR
aws ecr get-login-password --region us-east-1 | \
    docker login --username AWS --password-stdin \
    YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Tag and push
docker tag waf-app:latest YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/waf-app:latest
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/waf-app:latest

# Update ECS service
aws ecs update-service \
    --cluster waf-prod-cluster \
    --service waf-prod-service \
    --force-new-deployment \
    --region us-east-1
```

### 4. Database Setup

#### 4.1 Run Migrations

Option A: Using ECS Run Task

```bash
# Get task definition, subnet, and security group from the service
TASK_DEF=$(aws ecs describe-services --cluster waf-prod-cluster --services waf-prod-service --query 'services[0].taskDefinition' --output text)
SUBNET=$(aws ecs describe-services --cluster waf-prod-cluster --services waf-prod-service --query 'services[0].networkConfiguration.awsvpcConfiguration.subnets[0]' --output text)
SECURITY_GROUP=$(aws ecs describe-services --cluster waf-prod-cluster --services waf-prod-service --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups[0]' --output text)

# Run migration
aws ecs run-task \
    --cluster waf-prod-cluster \
    --task-definition $TASK_DEF \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[$SUBNET],securityGroups=[$SECURITY_GROUP],assignPublicIp=ENABLED}" \
    --overrides '{"containerOverrides":[{"name":"waf-app","command":["python","manage.py","migrate"]}]}' \
    --region us-east-1
```

Option B: Using ECS Exec (requires enabling ECS Exec on the service)

```bash
# Enable ECS Exec
aws ecs update-service \
    --cluster waf-prod-cluster \
    --service waf-prod-service \
    --enable-execute-command \
    --region us-east-1

# Get a running task ID
TASK_ID=$(aws ecs list-tasks --cluster waf-prod-cluster --service-name waf-prod-service --query 'taskArns[0]' --output text)

# Execute migration
aws ecs execute-command \
    --cluster waf-prod-cluster \
    --task $TASK_ID \
    --container waf-app \
    --interactive \
    --command "python manage.py migrate"
```

#### 4.2 Create Superuser

```bash
aws ecs execute-command \
    --cluster waf-prod-cluster \
    --task $TASK_ID \
    --container waf-app \
    --interactive \
    --command "python manage.py createsuperuser"
```

### 5. GeoIP Database Setup

#### 5.1 Download GeoLite2 Database

1. Sign up at https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-Country.mmdb
3. Place it in `waf_project/geoip/` directory before building the Docker image

Or mount it as a volume in production.

### 6. Configure Custom Domain (Optional)

#### 6.1 Create Route 53 Hosted Zone

```bash
aws route53 create-hosted-zone \
    --name your-domain.com \
    --caller-reference $(date +%s)
```

#### 6.2 Create SSL Certificate

```bash
aws acm request-certificate \
    --domain-name your-domain.com \
    --subject-alternative-names www.your-domain.com \
    --validation-method DNS \
    --region us-east-1
```

#### 6.3 Update ALB Listener

Add HTTPS listener to the ALB with the SSL certificate.

#### 6.4 Create DNS Record

Point your domain to the ALB DNS name using Route 53 or your DNS provider.

## Local Testing with Docker Compose

Before deploying to AWS, test locally:

```bash
# Copy environment template
cp .env.example .env

# Edit .env with local settings
# Start services
docker-compose up -d

# Run migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Access application
open http://localhost:8000/admin
```

## Monitoring and Logging

### View Logs

```bash
# CloudWatch Logs
aws logs tail /ecs/waf-prod --follow --region us-east-1

# Or via AWS Console
# Navigate to CloudWatch > Log groups > /ecs/waf-prod
```

### Monitor ECS Service

```bash
# Service status
aws ecs describe-services \
    --cluster waf-prod-cluster \
    --services waf-prod-service \
    --region us-east-1

# Task status
aws ecs list-tasks \
    --cluster waf-prod-cluster \
    --service-name waf-prod-service \
    --region us-east-1
```

## Scaling

### Manual Scaling

```bash
aws ecs update-service \
    --cluster waf-prod-cluster \
    --service waf-prod-service \
    --desired-count 4 \
    --region us-east-1
```

### Auto Scaling

Create auto-scaling policies based on CPU/Memory utilization or custom metrics.

## Troubleshooting

### Container Won't Start

1. Check CloudWatch logs for errors
2. Verify environment variables and secrets
3. Ensure database is accessible from ECS tasks
4. Check security group rules

### Database Connection Issues

1. Verify RDS security group allows connections from ECS security group
2. Check DATABASE_URL or individual DB credentials
3. Ensure RDS instance is in the same VPC

### Health Check Failures

1. Ensure `/health/` endpoint exists in your Django app
2. Check health check settings in target group
3. Verify container is listening on port 8000

### Missing GeoIP Database

1. Download GeoLite2-Country.mmdb from MaxMind
2. Place in `waf_project/geoip/` before building
3. Rebuild and redeploy the Docker image

## Maintenance

### Update Application

```bash
# Make code changes
# Run deployment script
./deploy.sh
```

### Database Backup

RDS automatically creates daily backups. To create manual snapshot:

```bash
aws rds create-db-snapshot \
    --db-instance-identifier waf-prod-postgres \
    --db-snapshot-identifier waf-prod-snapshot-$(date +%Y%m%d) \
    --region us-east-1
```

### Update Secrets

```bash
aws secretsmanager update-secret \
    --secret-id waf/django-secret-key \
    --secret-string "new-secret-key" \
    --region us-east-1

# Restart ECS service to pick up new secrets
aws ecs update-service \
    --cluster waf-prod-cluster \
    --service waf-prod-service \
    --force-new-deployment \
    --region us-east-1
```

## Cost Optimization

- Use Fargate Spot for non-production environments
- Enable RDS auto-scaling storage
- Use CloudWatch Logs retention policies
- Consider Reserved Instances for predictable workloads
- Use S3 for static files instead of EFS

## Security Best Practices

- ✅ Use AWS Secrets Manager for sensitive data
- ✅ Enable VPC Flow Logs
- ✅ Use security groups with least privilege
- ✅ Enable CloudTrail for audit logging
- ✅ Regularly update Docker base images
- ✅ Enable AWS WAF on ALB (optional)
- ✅ Use HTTPS only in production
- ✅ Implement database encryption at rest

## Support

For issues or questions:
1. Check CloudWatch logs
2. Review ECS task events
3. Verify security group and network configuration
4. Consult AWS documentation

## Additional Resources

- [AWS ECS Documentation](https://docs.aws.amazon.com/ecs/)
- [Django Deployment Checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
