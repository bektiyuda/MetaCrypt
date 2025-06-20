# MetaCrypt

**MetaCrypt** is a Python tool to encrypt and decrypt GPS metadata (Exif) in image files using AES encryption. This tool is useful for protecting your privacy by securing location data embedded in photos.

---

## 🚀 Features

- 🔐 Encrypts GPS metadata (Latitude, Longitude, DateStamp, TimeStamp) with AES-128.
- 🔓 Decrypts and restores original metadata from encrypted images.
- 🖼️ Supports JPEG images with Exif metadata.
- 🧪 Sample images provided in the `samples/` folder.

---

## 📦 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-username/meta-crypt.git
   cd meta-crypt
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🔧 Usage

Run the script:
```bash
python metadata_enc.py
```

Follow the interactive menu:
```
=== Cryptography Metadata Menu ===
1. Metadata Encryption
2. Metadata Decryption
3. Exit
```

- Input the path to a JPEG image (e.g., `samples/DSCN0010.jpg`)
- Enter a 16-character AES encryption key.

---

## 📂 Sample Images

Example JPEG files with Exif metadata are available in the `samples/` directory for testing purposes.

---

## 🛡️ Security Notes

- The script uses **AES in ECB mode**, which is simple but not the most secure for large or sensitive data. Use this for educational or experimental purposes only.
- Encrypted metadata is stored in the `GPSMapDatum` field as Base64-encoded bytes.

---

## 📋 Dependencies

Listed in `requirements.txt`:
```
pycryptodome
Pillow
piexif
```

Install them via:
```bash
pip install -r requirements.txt
```

---

## 👨‍💻 Contributing

Contributions are welcome! Feel free to fork this project, open issues, or submit pull requests.