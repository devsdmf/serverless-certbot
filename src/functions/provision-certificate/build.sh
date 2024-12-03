#!/bin/sh

if [ -f "package.zip" ]; then
  rm package.zip
fi

if [ -d "build" ]; then
  rm -rf build/
fi

mkdir build && cd build
cp ../main.py .
cp ../requirements.txt .

pip install \
  --target . \
  --platform manylinux2014_x86_64 \
  --python-version 3.13 \
  --no-cache-dir \
  --no-deps \
  -r requirements.txt

rm -rf __pycache__

zip -r ../package.zip *
