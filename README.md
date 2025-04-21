# Lil' Crypt - File Manager (GUI)

A simple graphical user interface (GUI) tool for encrypting and decrypting files within a single, predefined folder using symmetric encryption.

## Features

* Easy-to-use GUI based on Tkinter.
* Operates exclusively on a single, predefined folder (`managed_files` by default).
* Encrypts all non-encrypted, unmapped files found in the managed folder.
* Decrypts all encrypted (`.enc`) files found in the managed folder that have corresponding manifest entries.
* Maintains an encryption key (`secret.key`) and a manifest file (`manifest.json`) mapping encrypted file UUIDs to original filenames.
* Option to automatically delete original files after successful encryption.
* Option to automatically delete encrypted (`.enc`) files after successful decryption (also removes manifest entry).
* Displays key and manifest status.
* Logs process output directly in the GUI.
* Allows viewing the manifest file content within the GUI.
* Button to quickly open the managed folder in your system's file explorer.

## Prerequisites

* Python 3.6 or higher.
* The `tkinter` library (usually included with Python).
* The `cryptography` library.

You can install the required libraries using pip:

```bash
pip install cryptography
