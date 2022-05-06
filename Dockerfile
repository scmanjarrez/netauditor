FROM instrumentisto/nmap

RUN apk add --no-cache musl-dev linux-headers gcc sqlite lua5.3 lua-sql-sqlite3 \
    python3 python3-dev py3-pip git && rm -rf /var/cache/apk/*
RUN ln -s /usr/lib/lua /usr/local/lib/lua
RUN git clone --depth 1 --recurse-submodules \
    https://gitlab.gast.it.uc3m.es/schica/CVEScannerV2

ENV APP_HOME=/CVEScannerV2
WORKDIR $APP_HOME
RUN git clone --depth 1 https://gitlab.gast.it.uc3m.es/schica/netauditor.git
RUN pip install wheel && pip install -r netauditor/requirements.txt
RUN cd CVEScannerV2DB && sh build.sh
RUN ln -s CVEScannerV2DB/cve.db cve.db

ENTRYPOINT ["/usr/bin/python3", "netauditor/netauditor.py"]
