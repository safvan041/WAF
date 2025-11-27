FROM nginx:1.25-alpine

# Remove default nginx config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our config
COPY nginx.conf /etc/nginx/conf.d/

# Create directories for static and media files (they will be mounted)
RUN mkdir -p /app/staticfiles /app/mediafiles
