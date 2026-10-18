#!/bin/sh
# Builds libyggdrasil.so (Yggdrasil-ng with JNI bindings, libs/yggdrasil-ng-jni)
# for every Android ABI into app/src/main/jniLibs.
#
# Needs: Rust with the Android targets, cargo-ndk, and ANDROID_NDK_HOME set to
# NDK r25 or newer:
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
#   cargo install cargo-ndk
set -e
cd "$(dirname "$0")/../libs/yggdrasil-ng-jni"
cargo ndk \
  --platform 21 \
  -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
  -o ../../app/src/main/jniLibs \
  build --release
