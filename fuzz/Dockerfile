FROM gcr.io/oss-fuzz-base/base-builder

RUN pip3 install --upgrade pip setuptools wheel && pip3 install atheris cryptography

COPY . "$SRC/kinegrant-protocol"
WORKDIR "$SRC/kinegrant-protocol"
COPY fuzz/build.sh "$SRC/"
