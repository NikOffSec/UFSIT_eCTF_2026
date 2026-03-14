start_time=$(date +%s%N)
uvx ectf tools /dev/ttyACM0 list 123
end_time=$(date +%s%N)
duration_ns=$((end_time - start_time))
duration_ms=$((duration_ns / 1000000))
echo "UVX List Command took ms: $duration_ms"
