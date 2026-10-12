#!/bin/bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
# probe.sh URL  -> prints Status/Files/Result/alert from the scan result
B=cookies.txt
HOST=https://spaceship.web.2026.sunshinectf.games
url="$1"
red=$(curl -s -m 60 -b $B -o /dev/null -w "%{http_code}|%{redirect_url}" -X POST $HOST/scan --data-urlencode "url=$url")
code=${red%%|*}; loc=${red##*|}
if [ "$code" = "400" ]; then echo "BLOCKED  $url"; exit 0; fi
if [ -z "$loc" ]; then echo "CODE$code  $url"; exit 0; fi
body=$(curl -s -m 20 -b $B "$loc")
status=$(echo "$body" | grep -A0 'Status' | grep -oP '(?<=<span class="v">)[^<]*' | head -1)
files=$(echo "$body" | grep -oP '(?<=<span class="v">)[^<]*' | sed -n '3p')
result=$(echo "$body" | grep -oP '(?<=<span class="v">)[^<]*' | sed -n '4p')
alert=$(echo "$body" | grep -oP '(?<=<div class="alert">)[^<]*')
img=$(echo "$body" | grep -oP '(?<=src=")/screenshots/[^"]*')
echo "OK $url :: status=$status files=$files result=$result :: alert=$alert :: img=$img :: $loc"
