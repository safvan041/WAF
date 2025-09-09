#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Starting project reorganization..."

# Navigate to the project root
ROOT_DIR=$(pwd)
echo "Current directory: $ROOT_DIR"

# Check if the required directories exist
if [ ! -d "waf_project" ] || [ ! -d "waf_core" ] || [ ! -d "waf_engine" ]; then
    echo "Error: Required directories (waf_project, waf_core, waf_engine) not found. Please ensure they are at the same level as this script."
    exit 1
fi

echo "Moving apps into the waf_project directory..."
mv waf_core waf_project/
mv waf_engine waf_project/

# Check if a 'templates' directory exists at the root, and move it if it does
if [ -d "templates" ]; then
    echo "Moving top-level 'templates' directory into waf_project..."
    mv templates waf_project/
fi

# Check if a 'static' directory exists at the root, and move it if it does
if [ -d "static" ]; then
    echo "Moving top-level 'static' directory into waf_project..."
    mv static waf_project/
fi

echo "Reorganization complete. Your new structure is:"
find waf_project -print -mindepth 1 | sed 's|^|  |' | sed 's|  |    |g'

echo "You can now delete the previous app directories from the root if they are empty."
echo "Please remember to update your Django settings to reflect the new paths."
echo "Example: INSTALLED_APPS = ['waf_project.waf_core', 'waf_project.waf_engine']"
