FROM ubuntu:bionic

ADD ./requirements.txt /usr/local/bin/app/requirements.txt

RUN set -x && \
    apt-get update && \
    apt-get install -y python3-pip && \
    pip3 install --no-cache-dir -r /usr/local/bin/app/requirements.txt && \
    apt-get purge -y python3-pip && \
    apt-get autoremove -y && \
    apt-get install -y python3.6 libpython3.6 && \
    apt-get clean -y && \
    apt-get autoclean -y && \
    rm -f /var/cache/apt/*.bin && \
    find /tmp -type f -delete && \
    find /var/tmp -type f -delete

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ADD . /usr/local/bin/app
CMD /usr/local/bin/app/start-prod

EXPOSE 5000