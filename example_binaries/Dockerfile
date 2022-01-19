FROM ubuntu

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y build-essential

RUN apt-get install -y gcc-9-aarch64-linux-gnu

