FROM kalilinux/kali-rolling:latest

RUN apt update && apt install -y \
    python3-pip \
    nmap \
    whatweb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY recon_tool.py .

ENTRYPOINT ["python3", "recon_tool.py"]
