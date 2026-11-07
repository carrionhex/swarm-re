#!/bin/bash
# Journey capture: one long shot, unknown duration -> fifo-stop ffmpeg (clean moov)
NAME=${1:-ad_journey_v1}
R="$HOME/ad_render"
D=99
pkill -f "[a]d_render" 2>/dev/null || true
sleep 1
pgrep Xvfb >/dev/null && pkill Xvfb && sleep 1
Xvfb :$D -screen 0 1920x1080x24 >/dev/null 2>&1 &
XPID=$!
sleep 2
rm -f /tmp/ffq_$NAME; mkfifo /tmp/ffq_$NAME
DISPLAY=:$D ffmpeg -y -loglevel error -f x11grab -video_size 1920x1080 -framerate 30 -i :$D \
 -c:v libx264 -preset veryfast -crf 22 -pix_fmt yuv420p \
 "$R/out/$NAME.mp4" <> /tmp/ffq_$NAME &
sleep 1
DISPLAY=:$D google-chrome --kiosk --window-size=1920,1080 \
 --enable-unsafe-swiftshader --use-gl=angle --use-angle=swiftshader \
 --no-first-run --disable-session-crashed-bubble --hide-scrollbars \
 --remote-debugging-port=9222 --remote-allow-origins=* \
 --user-data-dir=$R/profile_$NAME "https://carrionhex.com/" >/dev/null 2>&1 &
CPID=$!
sleep 8
$R/venv/bin/python $R/drive_journey.py
echo q > /tmp/ffq_$NAME
sleep 2
kill $CPID 2>/dev/null
kill $XPID 2>/dev/null
rm -f /tmp/ffq_$NAME
echo "CAPTURE_JOURNEY_DONE $NAME"
ffprobe -v error -show_entries format=duration,size -of default=nw=1 "$R/out/$NAME.mp4"
