# WAF Application - Quick Start

## Local Development with Docker Compose

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit .env with your settings (use defaults for local dev)

# 3. Start all services
docker-compose up -d

# 4. Run migrations
docker-compose exec web python manage.py migrate

# 5. Create superuser
docker-compose exec web python manage.py createsuperuser

# 6. Access the application
# Admin: http://localhost:8000/admin
# Application: http://localhost:8000
```

## AWS Deployment

See [AWS_DEPLOYMENT.md](./AWS_DEPLOYMENT.md) for complete deployment instructions.

### Quick Deploy

```bash
# Set environment variables
export AWS_ACCOUNT_ID=your-account-id
export AWS_REGION=us-east-1

# Run deployment
chmod +x deploy.sh
./deploy.sh
```

## Project Structure

```
waf_project/
├── Dockerfile                  # Production Docker image
├── docker-compose.yml          # Local development setup
├── requirements.txt            # Python dependencies
├── deploy.sh                   # AWS deployment script
├── AWS_DEPLOYMENT.md          # Detailed deployment guide
├── .env.example               # Environment variables template
├── scripts/
│   └── entrypoint.sh          # Container startup script
├── aws/
│   ├── cloudformation-template.yml  # Infrastructure as Code
│   ├── ecs-task-definition.json     # ECS task config
│   └── ecs-service.json             # ECS service config
└── waf_project/
    ├── settings.py            # Development settings
    ├── settings_production.py # Production settings
    ├── waf_core/              # Core application
    └── waf_engine/            # WAF engine
```

## Configuration Files

- **Dockerfile**: Multi-stage build for optimized production image
- **docker-compose.yml**: PostgreSQL + Redis + Django for local development
- **settings_production.py**: Production Django settings with environment variables
- **.env.example**: Template for all required environment variables
- **aws/cloudformation-template.yml**: Complete AWS infrastructure (VPC, RDS, ECS, ALB)

## Key Features

- ✅ Multi-tenant WAF system
- ✅ Docker containerization
- ✅ AWS ECS Fargate deployment
- ✅ PostgreSQL database with RDS
- ✅ Redis caching with ElastiCache
- ✅ Application Load Balancer
- ✅ CloudWatch logging
- ✅ Health check endpoints
- ✅ Automated deployment scripts
- ✅ Infrastructure as Code

## Requirements

- Python 3.11+
- Docker & Docker Compose
- AWS CLI (for deployment)
- PostgreSQL 16 (production)
- Redis 7 (optional, for caching)

## Environment Variables

See `.env.example` for all available configuration options.

## Support

For deployment issues, see the troubleshooting section in [AWS_DEPLOYMENT.md](./AWS_DEPLOYMENT.md).
