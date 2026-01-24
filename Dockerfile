FROM kalilinux/kali-rolling:latest

LABEL maintainer="CTF-AI Ultimate"
LABEL description="AI-powered CTF analysis tool with multi-provider support"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-magic \
    binwalk \
    exiftool \
    file \
    foremost \
    strings \
    zsteg \
    steghide \
    stegseek \
    tshark \
    wireshark \
    checksec.sh \
    gdb \
    radare2 \
    pdfinfo \
    poppler-utils \
    curl \
    wget \
    git \
    unzip \
    p7zip-full \
    unrar \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY requirements.txt .
COPY config.json .
COPY ctf-ai.py .
COPY ctfhunter.py .
COPY check_dependencies.py .
COPY modules/ modules/
COPY playbooks/ playbooks/

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Create output directory
RUN mkdir -p /app/output

# Set up aliases
RUN echo 'alias ctf-ai="python3 /app/ctf-ai.py"' >> ~/.bashrc && \
    echo 'alias ctfhunter="python3 /app/ctfhunter.py"' >> ~/.bashrc

# Expose port for potential web interface (future)
EXPOSE 8080

# Default command
CMD ["python3", "ctf-ai.py"]
