# AutoGen Data Science Image
FROM python:3.11-slim

# Install essential tools and PostgreSQL client libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    git \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /workspace

# Install Python packages in stages
RUN pip install --upgrade pip && \
    pip install --no-cache-dir wheel setuptools

RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

# Base packages
RUN pip install --no-cache-dir \
    pyautogen \
    openai \
    pandas \
    numpy \
    flask \
    sqlalchemy \
    python-dotenv \
    flask-sqlalchemy

# Packages that might need special handling
RUN pip install --no-cache-dir "psycopg2-binary" && \
    pip install --no-cache-dir "autogen[openai]" && \
    pip install --no-cache-dir "flaml[automl]"

# Expose Chainlit port
EXPOSE 8000

# Default run command (can still be overridden in docker-compose.yml)
# CMD ["chainlit", "hello", "--host", "0.0.0.0", "--port", "8000"]

# Copy your script (optional - better to mount for development)
# COPY orchestrator.py /workspace/orchestrator.py
