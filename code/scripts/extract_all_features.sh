#!/bin/bash
# Trich xuat features tu tat ca file pcap co san trong datasets/
# Chay: bash code/scripts/extract_all_features.sh

mkdir -p datasets/features

for pcap in datasets/*.pcap; do
    name=$(basename "$pcap" .pcap)
    csv="datasets/features/${name}.csv"
    
    # Chi skip neu CSV da co va co nhieu hon 2 dong (header + data)
    if [ -f "$csv" ]; then
        lines=$(wc -l < "$csv")
        if [ "$lines" -gt 2 ]; then
            echo "[SKIP] $csv da ton tai ($lines dong)"
            continue
        else
            echo "[REDO] $csv rong hoac chi co header, chay lai..."
            rm -f "$csv"
        fi
    fi
    
    size=$(stat -c%s "$pcap" 2>/dev/null || stat -f%z "$pcap" 2>/dev/null)
    echo "[*] Dang xu ly: $pcap ($size bytes) -> $csv"
    python3 code/feature_extraction.py "$pcap" "$csv"
    
    if [ -f "$csv" ]; then
        lines=$(wc -l < "$csv")
        if [ "$lines" -gt 1 ]; then
            echo "  [OK] Da tao $csv ($lines dong)"
        else
            echo "  [!] $csv chi co header, khong co du lieu"
            rm -f "$csv"
        fi
    else
        echo "  [!] THAT BAI: khong tao duoc $csv"
    fi
done

echo ""
echo "=== KET QUA ==="
ls -la datasets/features/*.csv 2>/dev/null || echo "Khong co file CSV nao!"
