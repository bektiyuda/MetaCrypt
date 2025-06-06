from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import piexif
import json
import base64
import os

def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded)

def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted, AES.block_size).decode()

def encrypt_metadata():
    path = input("Input image file path : ").strip()
    if not os.path.exists(path):
        print("File not found.")
        return

    key_input = input("Input AES key (16 characters): ").strip()
    if len(key_input) != 16:
        print("Length must be 16 characters.")
        return
    key = key_input.encode()

    try:
        image = Image.open(path)
        exif_data = piexif.load(image.info.get('exif', b''))

        gps = exif_data.get("GPS", {})
        gps_metadata = {}

        if piexif.GPSIFD.GPSLatitude in gps and piexif.GPSIFD.GPSLatitudeRef in gps:
            lat_ref = gps[piexif.GPSIFD.GPSLatitudeRef].decode('utf-8')
            lat = gps[piexif.GPSIFD.GPSLatitude]
            gps_metadata["LatitudeRef"] = lat_ref
            gps_metadata["Latitude"] = str(lat)

        if piexif.GPSIFD.GPSLongitude in gps and piexif.GPSIFD.GPSLongitudeRef in gps:
            lon_ref = gps[piexif.GPSIFD.GPSLongitudeRef].decode('utf-8')
            lon = gps[piexif.GPSIFD.GPSLongitude]
            gps_metadata["LongitudeRef"] = lon_ref
            gps_metadata["Longitude"] = str(lon)

        if piexif.GPSIFD.GPSDateStamp in gps:
            gps_date = gps[piexif.GPSIFD.GPSDateStamp].decode('utf-8')
            gps_metadata["DateStamp"] = gps_date

        if piexif.GPSIFD.GPSTimeStamp in gps:
            gps_time = gps[piexif.GPSIFD.GPSTimeStamp]
            gps_metadata["TimeStamp"] = str(gps_time)

        if not gps_metadata:
            print("No GPS metadata found.")
            return

        metadata_str = json.dumps(gps_metadata)
        print(f"\nEncrypted Metadata:\n{metadata_str}")

        encrypted = aes_encrypt(metadata_str, key)

        exif_data['GPS'] = {}

        exif_data['GPS'][piexif.GPSIFD.GPSMapDatum] = base64.b64encode(encrypted)

        dir_path = os.path.dirname(path)
        filename = "encrypted_" + os.path.basename(path)
        save_path = os.path.join(dir_path if dir_path else ".", filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        image.save(save_path, exif=piexif.dump(exif_data))
        print(f"Encrypted path : '{save_path}'.")

    except Exception as e:
        print("Something wrong with the encryption.")
        print(f"Error: {e}")

def decrypt_metadata():
    path = input("Input image file path : ").strip()
    if not os.path.exists(path):
        print("File not found.")
        return

    key_input = input("Input AES key (16 characters): ").strip()
    if len(key_input) != 16:
        print("Length must be 16 characters.")
        return
    key = key_input.encode()

    try:
        image = Image.open(path)
        exif_data = piexif.load(image.info.get('exif', b''))

        encrypted_b64 = exif_data['GPS'][piexif.GPSIFD.GPSMapDatum]
        encrypted_data = base64.b64decode(encrypted_b64)
        decrypted = aes_decrypt(encrypted_data, key)

        print(f"\nMetadata decryption success :\n{decrypted}")

        metadata = json.loads(decrypted)

        gps_data = {}

        if "LatitudeRef" in metadata:
            gps_data[piexif.GPSIFD.GPSLatitudeRef] = metadata["LatitudeRef"].encode('utf-8')
        if "Latitude" in metadata:
            gps_data[piexif.GPSIFD.GPSLatitude] = eval(metadata["Latitude"])
        if "LongitudeRef" in metadata:
            gps_data[piexif.GPSIFD.GPSLongitudeRef] = metadata["LongitudeRef"].encode('utf-8')
        if "Longitude" in metadata:
            gps_data[piexif.GPSIFD.GPSLongitude] = eval(metadata["Longitude"])
        if "DateStamp" in metadata:
            gps_data[piexif.GPSIFD.GPSDateStamp] = metadata["DateStamp"].encode('utf-8')
        if "TimeStamp" in metadata:
            gps_data[piexif.GPSIFD.GPSTimeStamp] = eval(metadata["TimeStamp"])

        exif_data["GPS"] = gps_data

        filename = "decrypted_" + os.path.basename(path)
        save_path = os.path.join(os.path.dirname(path), filename)
        image.save(save_path, exif=piexif.dump(exif_data))

        print(f"Decrypted file : '{filename}'.")

    except Exception as e:
        print("Something wrong with the decryption.")
        print(f"Error: {e}")

def main():
    while True:
        print("\n=== Cryptography Metadata Menu ===")
        print("1. Metadata Encryption")
        print("2. Metadata Decryption")
        print("3. Exit")

        choice = input("Choose menu: ").strip()
        if choice == '1':
            encrypt_metadata()
        elif choice == '2':
            decrypt_metadata()
        elif choice == '3':
            break
        else:
            print("Menu not valid.")

if __name__ == "__main__":
    main()