# 🔐 RC4 Encryption - Console Input Based

Welcome to a tiny but powerful C project that lets you **encrypt and decrypt your custom message using RC4** — one of the simplest and fastest stream ciphers ever created. And yes, it's got that hacker vibe built in.

## 🧠 What is RC4?

RC4 is a **stream cipher**—a kind of encryption algorithm that transforms your data byte by byte, mixing it with a stream of pseudo-random bytes. It was once used in protocols like SSL/TLS and WEP WiFi. Today, it's studied more for **learning** and **obfuscation techniques** in low-level programming and malware analysis.

You give it a **key**, and it whispers your secrets into unreadable gibberish. Later, give it the same key again... and like magic, your message is back. 🔁

---

## 🧾 Features

- ✅ Encrypt any custom message from the console.
- ✅ Decrypt the message back using the same RC4 logic.
- ✅ Works fully offline.
- ✅ Written in pure C.
- ✅ Cross-compiles easily on Windows with Visual Studio.

---

## 📥 How to Run

### Using Visual Studio (Windows):

1. 🧱 Create a new **Empty Project** in Visual Studio.
2. 📝 Add a new `.c` file (e.g., `main.c`) to the Source Files.
3. 💻 Copy-paste the code from `main.c` in this repo.
4. 🔨 Build the project (`Ctrl + Shift + B`).
5. ▶️ Run the project (`Ctrl + F5`).

---

## 🆚 Difference from Earlier (Hardcoded) Version

| Feature                     | Earlier Version (Hardcoded) | Current Version (User Input) |
|----------------------------|------------------------------|-------------------------------|
| Input Source               | Hardcoded string in code     | Console input from user       |
| Encryption/Decryption Flow | Fixed text only              | Works with any user message   |
| Flexibility                | Limited to single use-case   | Fully interactive             |
| Demo Experience            | Static output                | Feels like a real CLI tool    |
| Practicality               | Lower                        | More practical and testable   |

In the old version, the message `"Hacker in the pool BABY..."` was **baked into the code**. Every time you ran it, it did the same thing. Now, **you control the input** — making it better for learning and demos.

---

## 🚧 A Word of Suspense...

This RC4 implementation has a secret. Hidden deep inside its loops lies a mechanism — an unseen shuffle and a dance of bits — that can turn **plaintext into ciphertext and back again**... all without ever storing the key itself in memory beyond setup.

You don’t need to know why every variable is what it is. Just know this:

> Feed it a key, and it will protect your message like a vault.
> Feed it the same key again, and the vault opens.

But **mess with the key**, and... well, even you won’t be able to recover your secrets. 😈

---

## 📚 Credits

- Based on RC4 algorithm publicly available via [ORYX Embedded](https://www.oryx-embedded.com/doc/rc4_8c_source.html).
- Modified for educational use by [Yashodhan] by introducing runtime encryption with input oreinted context and keys.

## ⚠️ Disclaimer

This project is **for educational purposes only**. RC4 is no longer secure for real-world cryptography. Don’t use this to protect anything sensitive. But it’s a great way to learn the **fundamentals of encryption and stream cipher int**
