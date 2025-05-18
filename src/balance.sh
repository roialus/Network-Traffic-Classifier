#!/bin/sh

# Define Interfaces and IPs
INTERFACE1="enp0s31f6"
INTERFACE2="enx5c628bc1a021"
DEST_IP1="132.72.110.11"  
DEST_IP2="192.168.10.2"  
BIND_IP1="132.72.110.6"  
BIND_IP2="192.168.10.1"  
THRESHOLD=$((5 * 1024 * 1024))  # 5MB threshold
CHECK_INTERVAL=5  

# Start with INTERFACE1
CURRENT_INTERFACE=$INTERFACE1
CURRENT_DEST=$DEST_IP1
CURRENT_BIND=$BIND_IP1
TOTAL_BYTES=0  # Reset count at start

# Function to get the total bytes sent on an interface
get_traffic() {
    cat /sys/class/net/$1/statistics/tx_bytes 2>/dev/null || echo 0
}

# Function to start iPerf3 in the background
start_iperf() {
    echo "Starting iPerf3 on $CURRENT_INTERFACE ($CURRENT_BIND) to $CURRENT_DEST..."
    nohup iperf3 -c $CURRENT_DEST -B $CURRENT_BIND -p 5201 -b 10M -t 3600 > /tmp/iperf.log 2>&1 &
    sleep 2

    # Check if iPerf started correctly
    if ! pgrep -f "iperf3 -c"; then
        echo "ERROR: iPerf3 did not start!"
        cat /tmp/iperf.log
    fi
}

# Start iPerf on the first interface
start_iperf

# Get the initial byte count
PREV_BYTES=$(get_traffic $CURRENT_INTERFACE)

while true; do
    sleep $CHECK_INTERVAL

    # Get the current bytes transferred
    CURR_BYTES=$(get_traffic $CURRENT_INTERFACE)
    
    # Calculate the bytes transferred since last check
    DELTA_BYTES=$((CURR_BYTES - PREV_BYTES))
    
    # If the delta is negative, reset to zero (handles overflows)
    if [ $DELTA_BYTES -lt 0 ]; then
        DELTA_BYTES=0
    fi

    # Add to total bytes
    TOTAL_BYTES=$((TOTAL_BYTES + DELTA_BYTES))

    echo "Traffic on $CURRENT_INTERFACE: $DELTA_BYTES bytes (Total: $TOTAL_BYTES bytes)"

    # Check if we exceeded the threshold
    if [ $TOTAL_BYTES -ge $THRESHOLD ]; then
        echo "Threshold exceeded! Switching interfaces..."
        pkill -f "iperf3 -c"  # Stop current iPerf session

        # Switch to the other interface
        if [ "$CURRENT_INTERFACE" = "$INTERFACE1" ]; then
            CURRENT_INTERFACE=$INTERFACE2
            CURRENT_DEST=$DEST_IP2
            CURRENT_BIND=$BIND_IP2
        else
            CURRENT_INTERFACE=$INTERFACE1
            CURRENT_DEST=$DEST_IP1
            CURRENT_BIND=$BIND_IP1
        fi

        # Reset counter after switching
        TOTAL_BYTES=0
        PREV_BYTES=$(get_traffic $CURRENT_INTERFACE)

        # Restart iPerf on the new interface
        start_iperf
    fi

    # Update the previous byte counter
    PREV_BYTES=$CURR_BYTES
done
