import pyshark
import asyncio

eventloop = asyncio.new_event_loop()
asyncio.set_event_loop(eventloop)

capture = pyshark.LiveCapture("wlo1", eventloop=eventloop);

for packet in capture.sniff_continuously(100):
  print(packet)
