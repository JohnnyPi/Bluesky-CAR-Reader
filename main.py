import tkinter as tk
import customtkinter as ctk
import cbor2
import json
from tkinter import filedialog
from multiformats import CID, multihash, multicodec, varint
import threading

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


def safe_varint_decode(file):
    """Safely decode a varint from a file object."""
    value = 0
    shift = 0
    while True:
        byte = file.read(1)
        if not byte:
            raise EOFError("Unexpected end of file while decoding varint")
        i = ord(byte)
        value |= (i & 0x7f) << shift
        if not (i & 0x80):
            break
        shift += 7
    return value


class CARFileReader(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Modern CAR File Reader")
        self.geometry("1000x800")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.create_widgets()

    def create_widgets(self):
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # File selection
        self.file_frame = ctk.CTkFrame(self.main_frame)
        self.file_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.file_frame.grid_columnconfigure(1, weight=1)

        self.file_label = ctk.CTkLabel(self.file_frame, text="CAR File:")
        self.file_label.grid(row=0, column=0, padx=5, pady=5)

        self.file_entry = ctk.CTkEntry(self.file_frame, width=400)
        self.file_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.browse_button = ctk.CTkButton(self.file_frame, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=0, column=2, padx=5, pady=5)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.main_frame)
        self.progress_bar.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()  # Hide initially

        # Content display
        self.content_frame = ctk.CTkFrame(self.main_frame)
        self.content_frame.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        self.content_text = ctk.CTkTextbox(self.content_frame, wrap="word")
        self.content_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("CAR files", "*.car")])
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
            self.start_loading(filename)

    def start_loading(self, file_path):
        self.content_text.delete('1.0', tk.END)
        self.progress_bar.grid()  # Show progress bar
        self.progress_bar.set(0)

        # Start loading in a separate thread
        threading.Thread(target=self.load_car_file, args=(file_path,), daemon=True).start()

    def process_block(self, block_data, cid):
        try:
            parsed_data = cbor2.loads(block_data)
            if isinstance(parsed_data, dict):
                block_type = parsed_data.get('$type')
                if block_type == 'app.bsky.feed.post':
                    return {
                        'type': block_type,
                        'cid': str(cid),
                        'text': parsed_data.get('text', ''),
                        'createdAt': parsed_data.get('createdAt', ''),
                        'author': parsed_data.get('author', '')
                    }
                elif block_type:
                    return {'type': block_type}
            return {'type': f'unknown (codec: {cid.codec})'}
        except Exception as e:
            return {'type': f'error: {str(e)}'}

    def load_car_file(self, file_path):
        bluesky_posts = []
        block_types = {}

        try:
            with open(file_path, 'rb') as f:
                # Get file size for progress calculation
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)

                # Read the header
                header_length = safe_varint_decode(f)
                header_data = f.read(header_length)
                header = cbor2.loads(header_data)

                self.update_content(f"CAR File Version: {header['version']}\n")
                self.update_content(f"Root CIDs: {', '.join(str(cid) for cid in header['roots'])}\n\n")

                # Read blocks
                block_count = 0
                while f.tell() < file_size:
                    try:
                        block_length = safe_varint_decode(f)
                        if block_length == 0:
                            break

                        cid_bytes = self.read_cid(f)
                        cid = CID.decode(cid_bytes)

                        data_length = block_length - len(cid_bytes)
                        block_data = f.read(data_length)

                        # Process block data for Bluesky posts
                        block_info = self.process_block(block_data, cid)
                        if block_info:
                            block_type = block_info.get('type', 'unknown')
                            block_types[block_type] = block_types.get(block_type, 0) + 1
                            if block_type == 'app.bsky.feed.post':
                                bluesky_posts.append(block_info)

                        block_count += 1

                        # Update progress
                        progress = f.tell() / file_size
                        self.update_progress(progress)

                    except EOFError:
                        break
                    except Exception as e:
                        self.update_content(f"Error reading block {block_count}: {e}\n")
                        continue

                self.update_content(f"Total blocks processed: {block_count}\n")
                self.update_content("Block types found:\n")
                for block_type, count in block_types.items():
                    self.update_content(f"  {block_type}: {count}\n")
                self.update_content(f"\nBluesky Posts Found: {len(bluesky_posts)}\n\n")
                self.display_bluesky_posts(bluesky_posts)

        except Exception as e:
            self.update_content(f"Error loading CAR file: {e}\n")

        finally:
            self.update_progress(1)  # Ensure progress bar reaches 100%
            self.progress_bar.grid_remove()  # Hide progress bar when done

    def update_progress(self, value):
        self.after(0, self.progress_bar.set, value)

    def update_content(self, text):
        self.after(0, self.content_text.insert, tk.END, text)

    def read_cid(self, file):
        first_byte = file.read(1)
        if first_byte == b'\x12':
            # CIDv0
            if file.read(1) != b'\x20':
                raise ValueError("Invalid CIDv0")
            return b'\x12\x20' + file.read(32)
        else:
            # CIDv1
            file.seek(-1, 1)  # Go back one byte
            version = safe_varint_decode(file)
            if version != 1:
                raise ValueError(f"Unsupported CID version: {version}")
            codec = safe_varint_decode(file)
            mh_code = safe_varint_decode(file)
            mh_length = safe_varint_decode(file)
            mh_digest = file.read(mh_length)
            return varint.encode(version) + varint.encode(codec) + varint.encode(mh_code) + varint.encode(mh_length) + mh_digest

    def process_bluesky_post(self, block_data, cid):
        try:
            # Check if the CID codec is 'dag-cbor' (0x71)
            if cid.codec == 0x71:
                parsed_data = cbor2.loads(block_data)
                if isinstance(parsed_data, dict) and parsed_data.get('$type') == 'app.bsky.feed.post':
                    return {
                        'cid': str(cid),
                        'text': parsed_data.get('text', ''),
                        'createdAt': parsed_data.get('createdAt', ''),
                        'author': parsed_data.get('author', {}).get('did', '')
                    }
        except Exception as e:
            self.content_text.insert(tk.END, f"Error processing block: {e}\n")
        return None

    def display_bluesky_posts(self, posts):
        self.content_text.insert(tk.END, f"Bluesky Posts Found: {len(posts)}\n\n")
        for post in posts:
            self.content_text.insert(tk.END, f"CID: {post['cid']}\n")
            self.content_text.insert(tk.END, f"Author: {post['author']}\n")
            self.content_text.insert(tk.END, f"Created At: {post['createdAt']}\n")
            self.content_text.insert(tk.END, f"Text: {post['text']}\n\n")

if __name__ == "__main__":
    app = CARFileReader()
    app.mainloop()