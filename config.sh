#!/bin/bash
git submodule init
git submodule update
cd incubator-teaclave-sgx-sdk/
git apply --check ../sdk_for_eaa.patch
git am ../sdk_for_eaa.patch