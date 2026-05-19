import asyncio
from bleak import BleakScanner
from bleak import BleakClient

# BLE lock (global)
ble_lock = asyncio.Lock()

# Characteristic UUID for writing
WRITE_CHARACTERISTIC_UUID = "396a4501-f9b6-4644-b7d1-63abef3c00c3"
# Characteristic UUID for notifications
NOTIFY_CHARACTERISTIC_UUID = "396a4504-f9b6-4644-b7d1-63abef3c00c3"
MAX_PACKET_SIZE = 20
TIMEOUT = 15.0
ACK = b'\x02'
NACK = b'\x15'

async def discover_device_by_name(local_name):
    print(f"Scanning for device with local name: {local_name}")
    # Use return_adv=True so we read the local name from the advertisement
    # packet directly, bypassing the macOS CoreBluetooth name cache.
    devices = await BleakScanner.discover(return_adv=True)

    for address, (device, adv_data) in devices.items():
        name = adv_data.local_name
        # print(f"Device found with local name: {name}")
        if name and local_name in name: #or (local_name == "13" and name == "12"):
            print(f"Device found: {device.address}")
            return device.address

    print(f"No device found with local name: {local_name}")
    return None

# Alternative for thread safe executing on MacOS
async def run(address, message):
    async with BleakClient(address, timeout=TIMEOUT) as client:
        notification_data = None
        ack_event = asyncio.Event()
        loop = asyncio.get_running_loop()  # Capture the main event loop

        message_bytes = bytearray(message.encode())
        message_length = len(message_bytes)
        bytes_transmitted = 0

        def notification_handler(sender, data):
            print("Bytes Transmitted: " + str(bytes_transmitted))
            nonlocal notification_data
            notification_data = data
            loop.call_soon_threadsafe(ack_event.set)

        await client.start_notify(NOTIFY_CHARACTERISTIC_UUID, notification_handler)

        try:
            while bytes_transmitted < message_length:
                next_packet_size = min(MAX_PACKET_SIZE, message_length - bytes_transmitted)
                await client.write_gatt_char(WRITE_CHARACTERISTIC_UUID,
                                             message_bytes[bytes_transmitted:(bytes_transmitted + next_packet_size)])
                bytes_transmitted += next_packet_size

            # Wait for final notification
            await asyncio.wait_for(ack_event.wait(), timeout=TIMEOUT)

        except asyncio.TimeoutError:
            await client.disconnect()
            print("Timeout waiting for final notification. Transmission status unknown.")
        finally:
            await client.stop_notify(NOTIFY_CHARACTERISTIC_UUID)

        return notification_data

# async def run(address, message):
#     async with BleakClient(address, timeout=TIMEOUT) as client:
#         notification_data = None
#         ack_event = asyncio.Event()
#
#         message_bytes = bytearray(message.encode())
#         message_length = len(message_bytes)
#         bytes_transmitted = 0
#
#         def notification_handler(sender, data):
#             print("Bytes Transmitted: " + str(bytes_transmitted))
#             nonlocal notification_data
#             notification_data = data
#             ack_event.set()
#
#         await client.start_notify(NOTIFY_CHARACTERISTIC_UUID, notification_handler)
#
#         try:
#             while bytes_transmitted < message_length:
#                 next_packet_size = min(MAX_PACKET_SIZE, message_length - bytes_transmitted)
#                 await client.write_gatt_char(WRITE_CHARACTERISTIC_UUID,
#                                              message_bytes[bytes_transmitted:(bytes_transmitted + next_packet_size)])
#                 bytes_transmitted += next_packet_size
#
#             # Wait for final notification
#             await asyncio.wait_for(ack_event.wait(), timeout=TIMEOUT)
#
#         except asyncio.TimeoutError:
#             await client.disconnect()  # Force disconnect if timeout occurs
#             print("Timeout waiting for final notification. Transmission status unknown.")
#         finally:
#             await client.stop_notify(NOTIFY_CHARACTERISTIC_UUID)
#
#         return notification_data

async def handle_open(payload, ble_id):
    async with ble_lock:  # <-- Locking BLE operations here
        try:
            device_address = await discover_device_by_name(ble_id)
            if device_address:
                result = await asyncio.wait_for(run(device_address, payload), timeout=TIMEOUT)
                return result[0]  # Return first byte of notification (ACK/NACK)
            else:
                raise Exception("Exception error: lock not found")
                return 10
        except asyncio.TimeoutError:
            raise Exception("Exception error: timeout waiting for device")
            return 10
        except Exception as e:
            raise Exception(f"Exception error: {e}")
            return 10

