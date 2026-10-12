FROM debian:12-slim

# ruleid: sast.docker.remote-fetch-no-checksum
ADD https://example.com/releases/tool-1.2.3.tar.gz /opt/

# ruleid: sast.docker.remote-fetch-no-checksum
ADD --chown=app:app http://example.com/data.bin /data/data.bin

# ruleid: sast.docker.remote-fetch-no-checksum
RUN curl -fsSL https://example.com/install.sh | sh

# ruleid: sast.docker.remote-fetch-no-checksum
RUN wget -qO- https://example.com/setup.sh | sudo bash

# ruleid: sast.docker.remote-fetch-no-checksum
RUN apt-get update && \
    curl -fsSL https://example.com/bootstrap.sh | bash -s -- --quiet

# ruleid: sast.docker.remote-fetch-no-checksum
RUN curl -fsSLo /tmp/tool.tgz https://example.com/tool.tgz && \
    tar -xzf /tmp/tool.tgz -C /usr/local/bin

# ruleid: sast.docker.remote-fetch-no-checksum
RUN wget https://example.com/tool && chmod +x tool

# ok: sast.docker.remote-fetch-no-checksum
ADD --checksum=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 https://example.com/tool.tgz /opt/

# ok: sast.docker.remote-fetch-no-checksum
ADD ./local-file.tar.gz /opt/

# ok: sast.docker.remote-fetch-no-checksum
COPY config/app.conf /etc/app.conf

# ok: sast.docker.remote-fetch-no-checksum
RUN curl -fsSLo /tmp/tool.tgz https://example.com/tool.tgz && \
    echo "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  /tmp/tool.tgz" | sha256sum -c - && \
    tar -xzf /tmp/tool.tgz -C /usr/local/bin

# ok: sast.docker.remote-fetch-no-checksum
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates

# ok: sast.docker.remote-fetch-no-checksum
RUN curl -fsS https://example.com/healthz -o /dev/null

# ok: sast.docker.remote-fetch-no-checksum
RUN pip install --no-cache-dir -r requirements.txt
