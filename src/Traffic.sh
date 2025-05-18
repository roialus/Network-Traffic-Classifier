#!/bin/bash

# Where to save the dataset
BASE_DIR="./dataset"
mkdir -p "$BASE_DIR"

# List of apps and domains
declare -A APPS
APPS=(
  [Discord]="www.discord.com"
)

# Number of PCAPs per application
COUNT=30

# Page load wait time (in seconds)
WAIT_TIME=60

# Start capturing
for APP in "${!APPS[@]}"; do
  DOMAIN="${APPS[$APP]}"
  SAVE_DIR="$BASE_DIR/$APP"
  mkdir -p "$SAVE_DIR"
  echo "🚀 Capturing for $APP ($DOMAIN)"

  # Resolve IPs
  IPS=$(dig +short $DOMAIN | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
  FILTER=""
  for ip in $IPS; do
    FILTER="$FILTER or host $ip"
  done
  FILTER="${FILTER# or }"

  echo "📡 IP Filter for $APP: $FILTER"

  for ((i=1; i<=COUNT; i++)); do
    PCAP_PATH="$SAVE_DIR/${APP}_${i}.pcap"
    echo "📦 [$APP] Capturing session $i → $PCAP_PATH"

    # Start tcpdump
    sudo tcpdump -i any tcp and \( $FILTER \) -w "$PCAP_PATH" &
    TCPDUMP_PID=$!
    sleep 3

    # Start Xvfb if headless
    export DISPLAY=:99
    Xvfb :99 -screen 0 1024x768x24 &
    XVFB_PID=$!
    sleep 2

    # Clear Firefox cache
    rm -rf ~/.cache/mozilla/firefox/*
    rm -rf ~/.mozilla/firefox/*.default-release/cache2/*

    # Open Firefox in private mode
    firefox --new-window "https://$DOMAIN" &
    FIREFOX_PID=$!

    # Wait for traffic to be generated
    sleep $WAIT_TIME

    # Cleanup processes
    kill $TCPDUMP_PID >/dev/null 2>&1
    pkill -f "firefox.*$DOMAIN"
    kill $XVFB_PID >/dev/null 2>&1

    echo "✅ [$APP] Saved: $PCAP_PATH"
    echo "---------------------------"
  done
done

echo "🎉 All captures complete! PCAPs saved in $BASE_DIR"
