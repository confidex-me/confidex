FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
RUN apt-get update
RUN apt-get install -y --no-install-recommends python3 build-essential pkg-config libtss2-dev libxkbcommon-dev libwayland-dev libx11-dev libxi-dev libxcursor-dev libxrandr-dev libgl1-mesa-dev
RUN git config --global --add safe.directory /source
ENV CARGO_HOME=/source/.tools/cargo-linux
WORKDIR /source
ENTRYPOINT ["python3", "builders/linux/build.py"]
