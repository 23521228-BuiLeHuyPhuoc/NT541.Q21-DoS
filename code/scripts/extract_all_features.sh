#!/bin/bash
# Trich xuat features tu tat ca file pcap co san trong datasets/
# Chay: bash code/scripts/extract_all_features.sh

mkdir -p datasets/features

for pcap in datasets/*.pcap; do
    name=$(basename "$pcap" .pcap)
    csv="datasets/features/${name}.csv"
    
    if [ -f "$csv" ]; then
        echo "[SKIP] $csv da ton tai ($(wc -l < "$csv") dong)"
        continue
    fi
    
    size=$(stat -c%s "$pcap" 2>/dev/null || stat -f%z "$pcap" 2>/dev/null)
    echo "[*] Dang xu ly: $pcap ($size bytes) -> $csv"
    python3 code/feature_extraction.py "$pcap" "$csv"
    
    if [ -f "$csv" ]; then
        echo "  [OK] Da tao $csv ($(wc -l < "$csv") dong)"
    else
        echo "  [!] THAT BAI: khong tao duoc $csv"
    fi
done

echo ""
echo "=== KET QUA ==="
ls -la datasets/features/*.csv 2>/dev/null || echo "Khong co file CSV nao!"
