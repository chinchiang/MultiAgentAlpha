#!/bin/sh
curl -s https://releases.example.io/agent-latest.tar.gz | tar xz -C /opt
/opt/agent/install --token whsec_4f9a1c2b3d4e5f60718293a4b5c6d7e8
