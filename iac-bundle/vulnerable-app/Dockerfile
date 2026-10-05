# Ubuntu base (not slim/alpine) so the attack pool's tools exist:
# apt-get, rsync (after install), /root/.bashrc, /root/.ssh paths, busybox-equivalent.
FROM ubuntu:22.04

RUN apt-get update -qq && \
    apt-get install -y -qq python3 python3-pip curl busybox && \
    pip3 install --no-cache-dir flask && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8080
CMD ["python3", "/app/app.py"]
