# Pre-tooled image. Vanilla compose uses kalilinux/kali-rolling and you run
# /opt/adtk/bootstrap.sh once. Build this to bake the SAME rack in, so at
# runtime bootstrap is "ensure + verify", not "install from scratch":
#   docker build -t adtk-kali -f docker/Dockerfile .
# bootstrap.sh self-verifies the rack at the end of the build (nxc, nmap,
# hashcat, GetUserSPNs, secretsdump, getST, certipy, bloodyAD, ad-auto.py).
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV ADTK_LOGS=/logs
# Fat image only. Never set this on an SSH Kali — kali-linux-headless restarts
# networking mid-apt and can hang the box (see .refinements/2.md).
ENV ADTK_FULL_METAPACKAGE=1

COPY scripts/ /opt/adtk/
COPY conf/ /opt/adtk/conf/
COPY references/ /opt/adtk/references/

RUN chmod +x /opt/adtk/bootstrap.sh /opt/adtk/ad-auto.py /opt/adtk/bh-next.py /opt/adtk/mssql-hop.py \
 && /opt/adtk/bootstrap.sh

WORKDIR /logs
CMD ["sleep", "infinity"]
