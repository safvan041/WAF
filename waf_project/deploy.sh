#!/bin/bash
set -e

# Configuration
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID}"
ECR_REPOSITORY="${ECR_REPOSITORY:-waf-app}"
ECS_CLUSTER="${ECS_CLUSTER:-waf-prod-cluster}"
ECS_SERVICE="${ECS_SERVICE:-waf-prod-service}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}WAF Application Deployment Script${NC}"
echo -e "${GREEN}========================================${NC}"

# Check required environment variables
if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo -e "${RED}Error: AWS_ACCOUNT_ID environment variable is not set${NC}"
    exit 1
fi

# Step 1: Build Docker image
echo -e "\n${YELLOW}Step 1: Building Docker image...${NC}"
docker build -t ${ECR_REPOSITORY}:${IMAGE_TAG} .

if [ $? -ne 0 ]; then
    echo -e "${RED}Docker build failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker image built successfully${NC}"

# Step 2: Login to ECR
echo -e "\n${YELLOW}Step 2: Logging in to Amazon ECR...${NC}"
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

if [ $? -ne 0 ]; then
    echo -e "${RED}ECR login failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Logged in to ECR${NC}"

# Step 3: Tag image for ECR
echo -e "\n${YELLOW}Step 3: Tagging image for ECR...${NC}"
docker tag ${ECR_REPOSITORY}:${IMAGE_TAG} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${IMAGE_TAG}

echo -e "${GREEN}✓ Image tagged${NC}"

# Step 4: Push image to ECR
echo -e "\n${YELLOW}Step 4: Pushing image to ECR...${NC}"
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPOSITORY}:${IMAGE_TAG}

if [ $? -ne 0 ]; then
    echo -e "${RED}Image push failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Image pushed to ECR${NC}"

# Step 5: Update ECS service
echo -e "\n${YELLOW}Step 5: Updating ECS service...${NC}"
aws ecs update-service \
    --cluster ${ECS_CLUSTER} \
    --service ${ECS_SERVICE} \
    --force-new-deployment \
    --region ${AWS_REGION}

if [ $? -ne 0 ]; then
    echo -e "${RED}ECS service update failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ ECS service updated${NC}"

# Step 6: Wait for deployment to complete
echo -e "\n${YELLOW}Step 6: Waiting for deployment to stabilize...${NC}"
aws ecs wait services-stable \
    --cluster ${ECS_CLUSTER} \
    --services ${ECS_SERVICE} \
    --region ${AWS_REGION}

if [ $? -ne 0 ]; then
    echo -e "${RED}Deployment did not stabilize${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Deployment completed successfully${NC}"

# Step 7: Run database migrations (optional)
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo -e "\n${YELLOW}Step 7: Running database migrations...${NC}"
    
    # Get the task definition ARN
    TASK_DEF=$(aws ecs describe-services \
        --cluster ${ECS_CLUSTER} \
        --services ${ECS_SERVICE} \
        --region ${AWS_REGION} \
        --query 'services[0].taskDefinition' \
        --output text)
    
    # Get subnet and security group from the service
    SUBNET=$(aws ecs describe-services \
        --cluster ${ECS_CLUSTER} \
        --services ${ECS_SERVICE} \
        --region ${AWS_REGION} \
        --query 'services[0].networkConfiguration.awsvpcConfiguration.subnets[0]' \
        --output text)
    
    SECURITY_GROUP=$(aws ecs describe-services \
        --cluster ${ECS_CLUSTER} \
        --services ${ECS_SERVICE} \
        --region ${AWS_REGION} \
        --query 'services[0].networkConfiguration.awsvpcConfiguration.securityGroups[0]' \
        --output text)
    
    # Run migration task
    aws ecs run-task \
        --cluster ${ECS_CLUSTER} \
        --task-definition ${TASK_DEF} \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[${SUBNET}],securityGroups=[${SECURITY_GROUP}],assignPublicIp=ENABLED}" \
        --overrides '{"containerOverrides":[{"name":"waf-app","command":["python","manage.py","migrate"]}]}' \
        --region ${AWS_REGION}
    
    echo -e "${GREEN}✓ Migration task started${NC}"
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment completed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
