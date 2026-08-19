# Pre-tooled image. Vanilla compose uses kalilinux/kali-rolling and you run
# /opt/gotad/bootstrap.sh once. Build this to bake the SAME rack in, so at
# runtime bootstrap is "ensure + verify", not "install from scratch":
#   docker build -t gotad-kali -f docker/Dockerfile .
# bootstrap.sh self-verifies the rack at the end of the build (nxc, nmap,
# hashcat, GetUserSPNs, secretsdump, getST, certipy, bloodyAD, ad-auto.py).
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GOTAD_LOOT=/loot

COPY scripts/ /opt/gotad/
COPY conf/ /opt/gotad/conf/
COPY references/ /opt/gotad/references/

RUN chmod +x /opt/gotad/bootstrap.sh /opt/gotad/ad-auto.py /opt/gotad/bh-next.py /opt/gotad/mssql-hop.py \
 && /opt/gotad/bootstrap.sh

WORKDIR /loot
CMD ["sleep", "infinity"]
