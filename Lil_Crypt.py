import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel
import os
import json
import uuid
import sys
from cryptography.fernet import Fernet, InvalidToken

# ---------- Folder Setup ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TARGET_FOLDER = os.path.join(BASE_DIR, 'managed_files')
KEY_FILE = os.path.join(BASE_DIR, 'secret.key')
MANIFEST_FILE = os.path.join(BASE_DIR, 'manifest.json')
# ----------- End Folder Setup ------------

# ----------- GUI Setup ----------------
class lil_crypt:
    def __init__(self, master):
        self.master = master
        master.title("Lil' Crypt")
        master.geometry("600x700")

        # ------ Color Setup (Dark Mode) ------
        self.bg_color = "#2e2e2e"
        self.fg_color = "#ffffff"
        self.button_bg = "#555555"
        self.button_fg = "#ffffff"
        self.entry_bg = "#444444"
        self.entry_fg = "#ffffff"
        self.border_color = "#666666"
        self.text_area_bg = "#3c3c3c"
        self.text_area_fg = "#ffffff"
        self.checkbox_bg = self.bg_color

        master.configure(bg=self.bg_color)
        # --------- End Color Setup ----------

        # ------ Widgets & Button Setup ------
        self.status_frame = tk.Frame(master, bg=self.bg_color)
        self.status_frame.pack(pady=10)

        self.key_status_label = tk.Label(self.status_frame, text="Key Status: Checking...", bg=self.bg_color, fg=self.fg_color, font=('Arial', 10))
        self.key_status_label.pack(side=tk.LEFT, padx=10)

        self.manifest_status_label = tk.Label(self.status_frame, text="Manifest Status: Checking...", bg=self.bg_color, fg=self.fg_color, font=('Arial', 10))
        self.manifest_status_label.pack(side=tk.LEFT, padx=10)

        self.managed_folder_label = tk.Label(master, text=f"Managing Folder: {TARGET_FOLDER}", bg=self.bg_color, fg=self.fg_color, font=('Arial', 10, 'italic'))
        self.managed_folder_label.pack(pady=5)

        # action buttons frame
        self.action_buttons_frame = tk.Frame(master, bg=self.bg_color)
        self.action_buttons_frame.pack(pady=10)

        self.encrypt_button = tk.Button(self.action_buttons_frame, text="Encrypt New Files", command=self.start_encryption, bg=self.button_bg, fg=self.button_fg, activebackground=self.button_bg, activeforeground=self.button_fg, relief="raised", bd=2, width=25, height=2)
        self.encrypt_button.pack(side=tk.LEFT, padx=10)

        self.decrypt_button = tk.Button(self.action_buttons_frame, text="Decrypt Encrypted Files", command=self.start_decryption, bg=self.button_bg, fg=self.button_fg, activebackground=self.button_bg, activeforeground=self.button_fg, relief="raised", bd=2, width=25, height=2)
        self.decrypt_button.pack(side=tk.LEFT, padx=10)

        # open managed folder button
        self.open_folder_button = tk.Button(master, text="Open Managed Folder", command=self.open_managed_folder, bg=self.button_bg, fg=self.button_fg, activebackground=self.button_bg, activeforeground=self.button_fg, relief="raised", bd=2)
        self.open_folder_button.pack(pady=5)

        # options frame (check boxes)
        self.options_frame = tk.Frame(master, bg=self.bg_color)
        self.options_frame.pack(pady=10)

        self.delete_original_var = tk.BooleanVar()
        self.delete_original_checkbox = tk.Checkbutton(self.options_frame, text="Delete original after encryption", variable=self.delete_original_var, onvalue=True, offvalue=False, bg=self.checkbox_bg, fg=self.fg_color, selectcolor=self.button_bg, activebackground=self.checkbox_bg, activeforeground=self.fg_color)
        self.delete_original_checkbox.pack(anchor=tk.W)

        self.delete_encrypted_var = tk.BooleanVar()
        self.delete_encrypted_checkbox = tk.Checkbutton(self.options_frame, text="Delete encrypted after decryption", variable=self.delete_encrypted_var, onvalue=True, offvalue=False, bg=self.checkbox_bg, fg=self.fg_color, selectcolor=self.button_bg, activebackground=self.checkbox_bg, activeforeground=self.fg_color)
        self.delete_encrypted_checkbox.pack(anchor=tk.W)

        # output area
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', bg=self.text_area_bg, fg=self.text_area_fg, insertbackground=self.text_area_fg, borderwidth=2, relief="solid", highlightbackground=self.border_color, highlightcolor=self.border_color, font=('Consolas', 10))
        self.output_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # bottom buttons frame (view manifest and clear)
        self.bottom_buttons_frame = tk.Frame(master, bg=self.bg_color)
        self.bottom_buttons_frame.pack(pady=10)

        # view manifest button
        self.view_manifest_button = tk.Button(self.bottom_buttons_frame, text="View Manifest Log", command=self.view_manifest, bg=self.button_bg, fg=self.button_fg, activebackground=self.button_bg, activeforeground=self.button_fg, relief="raised", bd=2)
        self.view_manifest_button.pack(side=tk.LEFT, padx=10)

        # clear output button
        self.clear_output_button = tk.Button(self.bottom_buttons_frame, text="Clear Output", command=self.clear_output_text, bg=self.button_bg, fg=self.button_fg, activebackground=self.button_bg, activeforeground=self.button_fg, relief="raised", bd=2)
        self.clear_output_button.pack(side=tk.LEFT, padx=10)
        # -------- End Widgets & Button Setup ---------

        self.check_status()
        # make sure the managed folder exists on startup
        os.makedirs(TARGET_FOLDER, exist_ok=True)

    # print the output
    def log_output(self, message, color=None):
        # color the output
        self.output_text.config(state='normal')
        if color:
            if color == "red":
                self.output_text.tag_config("red", foreground="red")
            elif color == "green":
                self.output_text.tag_config("green", foreground="lightgreen")
            elif color == "yellow":
                self.output_text.tag_config("yellow", foreground="yellow")
            elif color == "cyan":
                self.output_text.tag_config("cyan", foreground="cyan")
            self.output_text.insert(tk.END, message + '\n', color)
        else:
            self.output_text.insert(tk.END, message + '\n')

        self.output_text.yview(tk.END) # auto-scroll to the bottom
        self.output_text.config(state='disabled')

    # clear the output area
    def clear_output_text(self):
        self.output_text.config(state='normal')
        self.output_text.delete('1.0', tk.END)
        self.output_text.config(state='disabled')
        # self.log_output("Output cleared.", color="cyan") # DEBUG

    # check the for keys and manifest file
    def check_status(self):
        # check key
        if os.path.exists(KEY_FILE):
            self.key_status_label.config(text="Key Status: Found", fg="lightgreen")
        else:
            self.key_status_label.config(text="Key Status: NOT Found", fg="red")
            # error if the key file is initially missing
            if not hasattr(self, '_initial_key_check_done'):
                 self.log_output("Warning: secret.key not found. Generating a new key is required before encryption.", color="yellow")
                 self._initial_key_check_done = True

        # check the manifest file
        if os.path.exists(MANIFEST_FILE):
            self.manifest_status_label.config(text="Manifest Status: Found", fg="lightgreen")
        else:
            self.manifest_status_label.config(text="Manifest Status: NOT Found", fg="orange")
            # log info if manifest is missing
            if not hasattr(self, '_initial_manifest_check_done'):
                 self.log_output("Info: manifest.json not found. A new one will be created on first encryption.", color="cyan")
                 self._initial_manifest_check_done = True

    # load the encryption key
    def load_key(self):
        try:
            with open(KEY_FILE, 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            self.log_output(f"Error: Key file not found at {KEY_FILE}", color="red")
            self.log_output("Please ensure secret.key is in the same directory as the script, or generate one.", color="red")
            return None
        except IOError as e:
            self.log_output(f"Error reading key file {KEY_FILE}: {e}", color="red")
            return None

    # load the manifest file or prefill it
    def load_manifest(self):
        try:
            with open(MANIFEST_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            self.log_output(f"Error decoding JSON from manifest file {MANIFEST_FILE}. It might be corrupted.", color="red")
            return None # Return None if corrupted
        except IOError as e:
            self.log_output(f"Error reading manifest file {MANIFEST_FILE}: {e}", color="red")
            return None # Return None if IO error

    # save data to the manifest file
    def save_manifest(self, manifest_data):
        try:
            with open(MANIFEST_FILE, 'w') as f:
                json.dump(manifest_data, f, indent=4)
        except IOError as e:
            self.log_output(f"Error writing manifest file {MANIFEST_FILE}: {e}", color="red")

    # generate and save a new key if the key file does not exist
    def generate_and_save_key_if_missing(self):
        if not os.path.exists(KEY_FILE):
            self.log_output("secret.key not found. Generating a new key...", color="yellow")
            try:
                key = Fernet.generate_key()
                with open(KEY_FILE, 'wb') as key_file:
                    key_file.write(key)
                self.log_output(f"Generated new encryption key and saved to {KEY_FILE}", color="green")
                self.check_status() # update the dashboard status
                return key
            except IOError as e:
                self.log_output(f"Error writing new key file {KEY_FILE}: {e}", color="red")
                return None
        else:
            return self.load_key() # load existing key if we have one

    # tidy up the manifest for old entries that are no longer needed
    def clean_manifest(self, manifest_data, target_directory):
        if not manifest_data:
            self.log_output(f"Manifest is empty. Nothing to clean for {target_directory}.", color="cyan")
            return manifest_data

        self.log_output(f"\nChecking for orphaned entries in manifest for directory: {target_directory}", color="cyan")

        # make sure the target folder exists
        if not os.path.isdir(target_directory):
             self.log_output(f"Error: Target directory '{target_directory}' not found for cleaning.", color="red")
             return manifest_data

        try:
            # Get UUIDs of .enc files in the target directory
            encrypted_files_in_target = {f[:-4] for f in os.listdir(target_directory)
                                       if os.path.isfile(os.path.join(target_directory, f))
                                       and f.lower().endswith('.enc')}
        # cannot clean if directory listing fails
        except OSError as e:
            self.log_output(f"Error listing files in directory {target_directory}: {e}", color="red")
            return manifest_data

        uuids_in_manifest = set(manifest_data.keys())
        orphaned_uuids = uuids_in_manifest - encrypted_files_in_target

        # if we find orphaned UUID's, clean the manifest
        if orphaned_uuids:
            self.log_output(f"Found {len(orphaned_uuids)} orphaned entries in manifest. Removing...", color="yellow")
            for uuid_key in list(orphaned_uuids):
                original_name = manifest_data.pop(uuid_key, "Unknown")
                self.log_output(f"  Removed entry for UUID '{uuid_key}' (Original: '{original_name}').", color="yellow")
            self.save_manifest(manifest_data) # save the manifest
            self.log_output("Manifest cleaned up and saved.", color="green")
        else:
            self.log_output("No orphaned entries found in manifest for this directory.", color="cyan")

        return manifest_data

    # encrypt a file & update the manifest
    def encrypt_file(self, filepath, key, manifest_data, delete_original):
        f = Fernet(key)
        original_filename = os.path.basename(filepath)
        source_directory = os.path.dirname(filepath)

        # check if this original filename is already a value in the manifest
        existing_uuid = next((u for u, name in manifest_data.items() if name == original_filename), None)
        if existing_uuid:
             # check if the corresponding encrypted file exists in the TARGET_FOLDER
             encrypted_filepath_check = os.path.join(TARGET_FOLDER, existing_uuid + '.enc')
             
             # if file is already handled
             if os.path.exists(encrypted_filepath_check):
                self.log_output(f"Skipping encryption of '{original_filename}' as its encrypted version '{os.path.basename(encrypted_filepath_check)}' is already in the manifest and exists.", color="yellow")
                return manifest_data
             else:
                 # manifest entry exists but the file does not... remove the orphaned entry.
                 self.log_output(f"Manifest entry found for '{original_filename}' (UUID {existing_uuid}), but encrypted file does not exist. Removing manifest entry.", color="yellow")
                 manifest_data.pop(existing_uuid, None)
                 self.save_manifest(manifest_data) # save & proceed

        # check if the file itself is already encrypted (ends with .enc)
        if filepath.lower().endswith('.enc'):
            self.log_output(f"Skipping '{original_filename}': File appears to be already encrypted (.enc extension).", color="yellow")
            return manifest_data

        try:
            # try to read the file
            try:
                with open(filepath, 'rb') as file:
                    file_data = file.read()
            except IOError as e:
                self.log_output(f"Error reading file {filepath}: {e}", color="red")
                return manifest_data

            # encrypt the file
            encrypted_data = f.encrypt(file_data)

            # generate a unique filename (UUID) for the encrypted file
            encrypted_filename_uuid = str(uuid.uuid4())
            # save the encrypted file to the TARGET_FOLDER
            encrypted_filepath = os.path.join(TARGET_FOLDER, encrypted_filename_uuid + '.enc')


            # try to write the encrypted file
            try:
                with open(encrypted_filepath, 'wb') as file:
                    file.write(encrypted_data)
                self.log_output(f"Encrypted '{original_filename}' to '{os.path.basename(encrypted_filepath)}'", color="green")

                # add the mapping to the manifest data
                manifest_data[encrypted_filename_uuid] = original_filename

                # option to delete the original file
                # only delete if the source file was in the TARGET_FOLDER
                if delete_original and source_directory == TARGET_FOLDER:
                    try:
                        os.remove(filepath)
                        self.log_output(f"Deleted original file: '{original_filename}' from managed folder.", color="green")
                    except OSError as e:
                        self.log_output(f"Error deleting original file {filepath}: {e}", color="red")
                elif delete_original and source_directory != TARGET_FOLDER:
                     self.log_output(f"Skipping deletion of '{original_filename}': Original file is not in the managed folder.", color="yellow")


                return manifest_data # return updated manifest

            # error encrypting... return the manifest
            except IOError as e:
                self.log_output(f"Error writing encrypted file {encrypted_filepath}: {e}", color="red")
                return manifest_data

        # else some other type of error... return the manifest
        except Exception as e:
            self.log_output(f"An unexpected error occurred while processing file {filepath}: {e}", color="red")
            return manifest_data

    # decrypt a file
    def decrypt_file(self, encrypted_filepath, key, manifest_data, delete_encrypted):
        """Decrypts a single .enc file using the manifest."""
        encrypted_filename = os.path.basename(encrypted_filepath)
        source_directory = os.path.dirname(encrypted_filepath)

        # ensure its the proper type of file to decrypt
        if not encrypted_filepath.lower().endswith('.enc'):
            self.log_output(f"Skipping '{encrypted_filename}': Not an encrypted file (.enc extension missing).", color="yellow")
            return manifest_data

        # get just the UUID
        encrypted_uuid = encrypted_filename[:-4]

        # look up the original filename in the manifest
        original_filename = manifest_data.get(encrypted_uuid)

        if not original_filename:
            self.log_output(f"Skipping '{encrypted_filename}': UUID not found in manifest. The file might be orphaned or corrupted.", color="yellow")
            return manifest_data

        # determine the path for the decrypted file (save to TARGET_FOLDER)
        decrypted_filepath = os.path.join(TARGET_FOLDER, original_filename)

        # check if the destination file already exists (original filename)
        if os.path.exists(decrypted_filepath):
            self.log_output(f"Skipping decryption of '{encrypted_filename}' as '{original_filename}' already exists in the managed folder.", color="yellow")
            return manifest_data

        try:
            # try to read the encrypted file
            try:
                with open(encrypted_filepath, 'rb') as file:
                    encrypted_data = file.read()
            except IOError as e:
                self.log_output(f"Error reading encrypted file {encrypted_filepath}: {e}", color="red")
                return manifest_data

            f = Fernet(key)
            
            # try to decrypt the data
            try:
                decrypted_data = f.decrypt(encrypted_data)
            except InvalidToken:
                self.log_output(f"Error: Could not decrypt file {encrypted_filepath}. The key may be incorrect or the file is corrupted.", color="red")
                return manifest_data

            # try to write the decrypted file
            try:
                with open(decrypted_filepath, 'wb') as file:
                    file.write(decrypted_data)
                self.log_output(f"Decrypted '{encrypted_filename}' to '{original_filename}' in managed folder.", color="green")

                # option to delete the encrypted file and remove from manifest
                # only delete if the source file was inside TARGET_FOLDER
                if delete_encrypted and source_directory == TARGET_FOLDER:
                    try:
                        os.remove(encrypted_filepath)
                        self.log_output(f"Deleted encrypted file: '{encrypted_filename}' from managed folder.", color="green")
                        # remove from manifest *only* if encrypted file is successfully deleted
                        if encrypted_uuid in manifest_data:
                            manifest_data.pop(encrypted_uuid)
                            self.log_output(f"Removed manifest entry for UUID '{encrypted_uuid}'.", color="green")
                    except OSError as e:
                        self.log_output(f"Error deleting encrypted file {encrypted_filepath}: {e}", color="red")
                elif delete_encrypted and source_directory != TARGET_FOLDER:
                     self.log_output(f"Skipping deletion of '{encrypted_filename}': Encrypted file is not in the managed folder.", color="yellow")

                return manifest_data

            except IOError as e:
                self.log_output(f"Error writing decrypted file {decrypted_filepath}: {e}", color="red")
                return manifest_data

        # other errors
        except Exception as e:
            self.log_output(f"An unexpected error occurred while processing file {encrypted_filepath}: {e}", color="red")
            return manifest_data

    # start encryption process
    def start_encryption(self):
        self.log_output("\n--- Starting Encryption Process (Managed Folder) ---", color="cyan")
        self.clear_output_text() # clear output

        # ensure TARGET_FOLDER exists
        os.makedirs(TARGET_FOLDER, exist_ok=True)

        # load/generate the encryption key
        key = self.generate_and_save_key_if_missing()
        if not key:
            self.log_output("Encryption failed: Could not load or generate key.", color="red")
            self.check_status()
            return

        # load the manifest file
        manifest_data = self.load_manifest()
        if manifest_data is None:
            self.log_output("Encryption failed: Could not load or create manifest.", color="red")
            self.check_status()
            return

        # iterate through files in the managed folder and encrypt them
        self.log_output(f"Looking for new unencrypted files in: {TARGET_FOLDER}", color="cyan")
        
        files_to_encrypt = []
        manifest_original_filenames = set(manifest_data.values())

        try:
            for filename in os.listdir(TARGET_FOLDER):
                filepath = os.path.join(TARGET_FOLDER, filename)
                # if it's a file, not already encrypted, and not in the manifest
                if os.path.isfile(filepath) and not filename.lower().endswith('.enc') and filename not in manifest_original_filenames:
                     files_to_encrypt.append(filepath)
        except OSError as e:
            self.log_output(f"Error listing files in directory {TARGET_FOLDER}: {e}", color="red")
            self.log_output("--- Encryption Process Finished ---", color="cyan")
            return

        # no valid files are in the TARGET_FOLDER
        if not files_to_encrypt:
            self.log_output(f"No new unencrypted files found in '{TARGET_FOLDER}' to encrypt.", color="yellow")
            self.log_output("--- Encryption Process Finished ---", color="cyan")
            self.check_status()
            return

        delete_original = self.delete_original_var.get()
        processed_count = 0
        for filepath in files_to_encrypt:
            # pass the delete_original flag and the manifest data
            manifest_data = self.encrypt_file(filepath, key, manifest_data, delete_original)
            processed_count += 1

        # save the updated manifest after processing all files
        if processed_count > 0:
             self.save_manifest(manifest_data)
             self.check_status() # update manifest status label
             self.log_output("\n--- Encryption Process Finished. Manifest updated. ---", color="cyan")
        else:
             self.log_output("\n--- Encryption Process Finished (no files processed). ---", color="cyan")


    # start the decryption process for files in the TARGET_FOLDER
    def start_decryption(self):
        """Initiates the decryption process for files in the managed folder."""
        self.log_output("\n--- Starting Decryption Process (Managed Folder) ---", color="cyan")
        self.clear_output_text()

        # make sure the TARGET_FOLDER exists
        os.makedirs(TARGET_FOLDER, exist_ok=True)

        # load the encryption key
        key = self.load_key()
        if not key:
            self.log_output("Decryption failed: Could not load key.", color="red")
            self.check_status()
            return

        # load the manifest file
        manifest_data = self.load_manifest()
        if manifest_data is None:
            self.log_output("Decryption failed: Could not load manifest. Ensure manifest.json is in the same directory.", color="red")
            self.check_status()
            return
        if not manifest_data:
             self.log_output("Manifest is empty. No files to decrypt.", color="yellow")
             self.log_output("--- Decryption Process Finished ---", color="cyan")
             self.check_status()
             return

        # clean up orphaned entries in the manifest based on the managed folder
        manifest_data = self.clean_manifest(manifest_data, TARGET_FOLDER)
        if manifest_data is None: # check again in case clean_manifest returned None due to save error
             self.log_output("Decryption failed after manifest cleanup.", color="red")
             self.check_status()
             return


        # iterate through files in the managed folder and decrypt them using the cleaned manifest
        self.log_output(f"\nLooking for encrypted files (.enc) in: {TARGET_FOLDER}", color="cyan")

        # get the list of encrypted files actually present in the managed folder
        files_to_decrypt = []
        try:
            for filename in os.listdir(TARGET_FOLDER):
                filepath = os.path.join(TARGET_FOLDER, filename)
                if os.path.isfile(filepath) and filename.lower().endswith('.enc'):
                     file_uuid = filename[:-4]
                     if file_uuid in manifest_data:
                         files_to_decrypt.append(filepath)
                     else:
                         self.log_output(f"Skipping '{filename}': Encrypted file found, but UUID '{file_uuid}' is not in the manifest.", color="yellow")
        except OSError as e:
            self.log_output(f"Error listing files in directory {TARGET_FOLDER}: {e}", color="red")
            self.log_output("--- Decryption Process Finished ---", color="cyan")
            return


        if not files_to_decrypt:
            self.log_output(f"No decryptable files (.enc files with manifest entries) found in '{TARGET_FOLDER}'.", color="yellow")
            self.log_output("--- Decryption Process Finished ---", color="cyan")
            self.check_status()
            return

        delete_encrypted = self.delete_encrypted_var.get()
        processed_count = 0
        for filepath_enc in files_to_decrypt:
            # pass the delete_encrypted flag and the manifest data
             manifest_data = self.decrypt_file(filepath_enc, key, manifest_data, delete_encrypted)
             processed_count += 1

        # save the manifest after processing all files
        if processed_count > 0:
             self.save_manifest(manifest_data)
             self.check_status() # update status labels
             self.log_output("\n--- Decryption Process Finished. Manifest updated. ---", color="cyan")
        else:
             self.log_output("\n--- Decryption Process Finished (no files processed). ---", color="cyan")

    def view_manifest(self):
        """Loads and displays the manifest file content in a new window."""
        manifest_data = self.load_manifest()

        if manifest_data is None: # handle errors loading manifest
            messagebox.showerror("Error", "Could not load manifest file due to an error.")
            return

        if not manifest_data:
            messagebox.showinfo("Manifest Log", "Manifest file is empty.")
            return

        # create a new top-level window for the manifest log
        manifest_window = Toplevel(self.master)
        manifest_window.title("Manifest Log")
        manifest_window.geometry("500x400")
        manifest_window.configure(bg=self.bg_color) # apply dark mode

        # scrolled text widget to display the manifest content
        manifest_text = scrolledtext.ScrolledText(manifest_window, wrap=tk.WORD, state='disabled', bg=self.text_area_bg, fg=self.text_area_fg, insertbackground=self.text_area_fg, borderwidth=2, relief="solid", highlightbackground=self.border_color, highlightcolor=self.border_color, font=('Consolas', 10))
        manifest_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        # display the formatted manifest data
        try:
            manifest_content = json.dumps(manifest_data, indent=4)
            manifest_text.config(state='normal')
            manifest_text.insert(tk.END, manifest_content)
            manifest_text.config(state='disabled')
        except Exception as e:
            manifest_text.config(state='normal')
            manifest_text.insert(tk.END, f"Error displaying manifest content: {e}")
            manifest_text.config(state='disabled')
            self.log_output(f"Error displaying manifest content: {e}", color="red")

    # open the folder (OS specific)
    def open_folder(self, folder_path):
        """Opens the specified folder in the system's file explorer."""
        if not os.path.exists(folder_path):
            self.log_output(f"Error: Folder not found at {folder_path}", color="red")
            messagebox.showerror("Error", f"Folder not found:\n{folder_path}")
            return

        try:
            if sys.platform == "win32":
                os.startfile(os.path.realpath(folder_path))
            elif sys.platform == "darwin": # macOS
                os.system(f'open "{os.path.realpath(folder_path)}"')
            else: # linux variants
                os.system(f'xdg-open "{os.path.realpath(folder_path)}"')
            self.log_output(f"Opened folder: {folder_path}", color="cyan")
        except Exception as e:
            self.log_output(f"Error opening folder {folder_path}: {e}", color="red")
            messagebox.showerror("Error", f"Could not open folder:\n{folder_path}\n{e}")

    # open the TARGET_FOLDER
    def open_managed_folder(self):
        """Opens the predefined managed folder."""
        self.open_folder(TARGET_FOLDER)

if __name__ == "__main__":
    root = tk.Tk()
    gui = lil_crypt(root)
    root.mainloop()