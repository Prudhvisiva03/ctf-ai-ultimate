#!/bin/bash

# Configuration
VERSION=$(cat VERSION)
RELEASE_NAME="ctf-ai-ultimate-v$VERSION"
OUTPUT_DIR="release_builds"

echo "📦 Packaging CTF-AI Ultimate v$VERSION..."

# Create output directory
mkdir -p "$OUTPUT_DIR"

# update zip
echo "Creating ZIP archive..."
zip -r "$OUTPUT_DIR/$RELEASE_NAME.zip" \
    ctf-ai.py \
    ctfhunter.py \
    config.json \
    install.sh \
    requirements.txt \
    VERSION \
    README.md \
    LICENSE \
    DOCKER.md \
    FAQ.md \
    SECURITY.md \
    modules/ \
    playbooks/ \
    examples/ \
    -x "*.pyc" -x "__pycache__" -x "*.git*" -x "output/*"

echo "✅ Created $OUTPUT_DIR/$RELEASE_NAME.zip"
echo "🎉 Build complete!"
