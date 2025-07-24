import signal
import serial
import subprocess
import sys
import threading
import time

RFCOMM_DEVICE = "/dev/rfcomm0"
BT_ADDR = "D8:FD:ED:DA:BC:49"
CHANNEL = 1

ser = None
running = True


def calc_checksum(data: bytes) -> int:
    chk = 0
    for b in data:
        chk ^= b
    return chk


def build_command(payload: bytes) -> bytes:
    if len(payload) != 11:
        raise ValueError("Payload must be exactly 11 bytes")
    header = bytes([0xFF, 0x55])
    length_byte = bytes([0x11])
    cmd = header + length_byte + payload
    checksum = calc_checksum(cmd)
    return cmd + bytes([checksum])


COMMANDS = {
    "reset_wh": bytes(
        [0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "reset_ah": bytes(
        [0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "reset_time": bytes(
        [0x11, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "reset_all": bytes(
        [0x11, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "cmd_mode": bytes(
        [0x11, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "cmd_onoff": bytes(
        [0x11, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "cmd_plus": bytes(
        [0x11, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
    "cmd_minus": bytes(
        [0x11, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    ),
}


def rfcomm_bind(addr, channel=1, dev=RFCOMM_DEVICE):
    print(f"Binding {addr} on channel {channel} to {dev}...")
    subprocess.run(["sudo", "rfcomm", "release", dev[-1]], check=False)
    subprocess.run(["sudo", "rfcomm", "bind", dev[-1], addr, str(channel)], check=True)
    print("Bound successfully.")
    time.sleep(2)


def parse_packet(data: bytes):
    print(data)
    if len(data) != 36 or data[0] != 0xFF or data[1] != 0x55:
        print("Invalid header")
        return None

    payload = data[3:-1]

    try:
        voltage = int.from_bytes(payload[1:4], "big") / 10.0
        current = int.from_bytes(payload[4:7], "big") / 1000.0
        power = voltage * current
        charge = int.from_bytes(payload[7:10], "big") / 100.0
        energy = int.from_bytes(payload[10:14], "big") * 10.0
        temp = int.from_bytes(payload[21:23], "big")

        print(f"{voltage:.3f}V,{current:.3f}A,{charge:.3f}Ah,{energy:.3f}Wh,{temp}degC")
    except Exception as e:
        print(f"Error parsing payload: {e}")


def cleanup(signum, frame):
    global ser, running
    print("\nCleaning up and exiting...")
    running = False
    if ser and not ser.closed:
        ser.close()
        print(f"Closed {RFCOMM_DEVICE}")
    sys.exit(0)


def read_loop():
    global ser, running
    buffer = bytearray()
    PACKET_HEADER = b"\xff\x55"
    PACKET_LEN = 36
    while running:
        try:
            chunk = ser.read(36)
            if not chunk:
                continue
            print(f"Received: {len(chunk)} : {chunk.hex()}")

            buffer.extend(chunk)

            # Remove junk before header
            while len(buffer) >= 2 and buffer[0:2] != PACKET_HEADER:
                del buffer[0]

            # Process packets
            if len(buffer) < PACKET_LEN or buffer[0:2] != PACKET_HEADER:
                continue

            packet = buffer[:PACKET_LEN]
            buffer = buffer[PACKET_LEN:]
            parse_packet(packet)

        except Exception as e:
            print(f"Error reading device: {e}")
            break


def send_command(cmd_bytes):
    global ser
    if ser and not ser.closed:
        try:
            ser.write(cmd_bytes)
            ser.flush()
            print(f"Sent command: {cmd_bytes.hex()}")
        except Exception as e:
            print(f"Failed to send command: {e}")
    else:
        print("Device not open for writing")


def main():
    global ser, running

    cmd_name = None

    if len(sys.argv) >= 2:
        cmd_name = sys.argv[1]

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    rfcomm_bind(BT_ADDR, CHANNEL)

    ser = serial.Serial(RFCOMM_DEVICE, baudrate=9600, timeout=0.5)
    print(f"Opened {RFCOMM_DEVICE} for read/write.")

    reader_thread = threading.Thread(target=read_loop, daemon=True)
    reader_thread.start()

    if cmd_name:
        if cmd_name not in COMMANDS:
            print(f"Unknown command '{cmd_name}'")
            sys.exit(1)
        payload = COMMANDS[cmd_name]
        cmd_bytes = build_command(payload)
        send_command(cmd_bytes)
    else:
        print("No command specified. Just read data... (press Ctrl+C to exit)")

    while running:
        time.sleep(0.5)


if __name__ == "__main__":
    main()
