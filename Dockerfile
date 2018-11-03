FROM ubuntu:bionic

ADD ./requirements.txt /usr/local/bin/app/requirements.txt

RUN set -x && \
    apt-get update && \
    apt-get install -y python3.6 python3-pip build-essential libssl-dev libffi-dev python3-dev && \
    pip3 install --no-binary --no-cache-dir -r /usr/local/bin/app/requirements.txt && \
    apt-get purge -y python3-pip build-essential && \
    apt-get clean -y && \
    apt-get autoclean -y && \
    rm -f /var/cache/apt/*.bin && \
    find /tmp -type f -delete && \
    find /var/tmp -delete

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ADD . /usr/local/bin/app
CMD /usr/local/bin/app/start-prod

EXPOSE 5000
