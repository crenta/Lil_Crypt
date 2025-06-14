# Lil' Crypt - File Manager (GUI)

A simple graphical user interface (GUI) tool for encrypting and decrypting files within a single, predefined folder using symmetric encryption.

## Features

* Easy-to-use GUI based on Tkinter.
* Operates exclusively on a single, predefined folder (`managed_files` by default).
* Encrypts all non-encrypted, unmapped files found in the managed folder.
* Decrypts all encrypted (`.enc`) files found in the managed folder that have corresponding manifest entries.
* Maintains an encryption key (`secret.key`) and a manifest file (`manifest.json`) mapping encrypted file UUIDs to original filenames.
* Generates the key (`secret.key`) if one doesn't already exist
* Option to automatically delete original files after successful encryption.
* Option to automatically delete encrypted (`.enc`) files after successful decryption (also removes manifest entry).
* Displays key and manifest status.
* Logs process output directly in the GUI.
* Allows viewing the manifest file content within the GUI.
* Button to quickly open the managed folder in your system's file explorer.

## Warning
* The (`secret.key`) corresponse to your encrypted file... if you delete this key, you will lose access to any files encrypted with that key.

## Prerequisites

* Python 3.6 or higher.
* The `tkinter` library (usually included with Python).
* The `cryptography` library.

You can install the required libraries using pip:

```bash
  pip install cryptography
```
## License

This project is licensed under the MIT License.


#Copyright (c) [2025]
[Crenta] [All rights reserved].

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
THIS SOFTWARE IS PROVIDED BY [Crenta] “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL [Crenta] BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

