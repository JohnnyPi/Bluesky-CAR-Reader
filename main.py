import colorsys
import random
import re
import tkinter as tk
import customtkinter as ctk
import cbor2
from tkinter import filedialog

import fuzz
from multiformats import CID, varint
import threading

ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

def safe_varint_decode(file):
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
        self.grid_rowconfigure(1, weight=1)

        self.create_widgets()
        self.bluesky_posts = []
        self.filtered_posts = []
        self.current_post_index = 0
        self.posts_per_page = 10
        self.pastel_colors = self.generate_pastel_colors(20)  # Generate 20 pastel colors

    def create_widgets(self):
        # Header with search bar
        self.header_frame = ctk.CTkFrame(self, fg_color="#3B82F6", height=100)
        self.header_frame.grid(row=0, column=0, sticky="ew")
        self.header_frame.grid_columnconfigure(1, weight=1)
        self.header_frame.grid_propagate(False)

        self.search_label = ctk.CTkLabel(self.header_frame, text="Search:", text_color="white")
        self.search_label.grid(row=0, column=0, padx=(20, 5), pady=10)

        self.search_entry = ctk.CTkEntry(self.header_frame, width=400, fg_color="white", text_color="#1E3A8A")
        self.search_entry.grid(row=0, column=1, padx=5, pady=10, sticky="ew")
        self.search_entry.bind("<Return>", self.perform_search)

        self.search_button = ctk.CTkButton(self.header_frame, text="Search", command=self.perform_search,
                                           fg_color="#2563EB", hover_color="#1D4ED8", text_color="white")
        self.search_button.grid(row=0, column=2, padx=(5, 20), pady=10)

        # Sorting buttons
        self.sort_frame = ctk.CTkFrame(self.header_frame, fg_color="#3B82F6")
        self.sort_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=10, sticky="ew")

        self.sort_by_likes_button = ctk.CTkButton(self.sort_frame, text="Sort by Most Likes",
                                                  command=lambda: self.sort_posts('likes'), fg_color="#2563EB", hover_color="#1D4ED8",
                                                  text_color="white")
        self.sort_by_likes_button.grid(row=0, column=0, padx=5, pady=5)

        self.sort_by_replies_button = ctk.CTkButton(self.sort_frame, text="Sort by Replies",
                                                    command=lambda: self.sort_posts('replies'), fg_color="#2563EB",
                                                    hover_color="#1D4ED8", text_color="white")
        self.sort_by_replies_button.grid(row=0, column=1, padx=5, pady=5)

        self.sort_by_first_button = ctk.CTkButton(self.sort_frame, text="Sort by First",
                                                  command=lambda: self.sort_posts('first'), fg_color="#2563EB",
                                                  hover_color="#1D4ED8", text_color="white")
        self.sort_by_first_button.grid(row=0, column=2, padx=5, pady=5)

        self.sort_by_latest_button = ctk.CTkButton(self.sort_frame, text="Sort by Latest",
                                                   command=lambda: self.sort_posts('latest'), fg_color="#2563EB",
                                                   hover_color="#1D4ED8", text_color="white")
        self.sort_by_latest_button.grid(row=0, column=3, padx=5, pady=5)

        # Main content area (posts)
        self.main_frame = ctk.CTkFrame(self, fg_color="#F0F9FF")
        self.main_frame.grid(row=1, column=0, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=1)

        self.posts_frame = ctk.CTkScrollableFrame(self.main_frame, fg_color="#F0F9FF")
        self.posts_frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.posts_frame.grid_columnconfigure(0, weight=1)
        self.posts_frame.bind_all("<MouseWheel>", self.on_mousewheel)

        # Footer with file selection
        self.footer_frame = ctk.CTkFrame(self, fg_color="#E0F0FF", height=80)
        self.footer_frame.grid(row=2, column=0, sticky="ew")
        self.footer_frame.grid_columnconfigure(1, weight=1)
        self.footer_frame.grid_propagate(False)

        self.file_label = ctk.CTkLabel(self.footer_frame, text="CAR File:", text_color="#1E3A8A")
        self.file_label.grid(row=0, column=0, padx=(20, 5), pady=25)

        self.file_entry = ctk.CTkEntry(self.footer_frame, width=400, fg_color="white", text_color="#1E3A8A")
        self.file_entry.grid(row=0, column=1, padx=5, pady=25, sticky="ew")

        self.browse_button = ctk.CTkButton(self.footer_frame, text="Browse", command=self.browse_file, fg_color="#3B82F6", hover_color="#2563EB", text_color="white")
        self.browse_button.grid(row=0, column=2, padx=(5, 20), pady=25)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.footer_frame, fg_color="#E0F0FF", progress_color="#3B82F6")
        self.progress_bar.grid(row=1, column=0, columnspan=3, padx=20, pady=(0, 10), sticky="ew")
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()

    def sort_posts(self, sort_by):
        if sort_by == 'likes':
            self.filtered_posts.sort(key=lambda post: post.get('likes', 0), reverse=True)
        elif sort_by == 'replies':
            self.filtered_posts.sort(key=lambda post: post.get('replies', 0), reverse=True)
        elif sort_by == 'first':
            self.filtered_posts.sort(key=lambda post: post.get('createdAt', ''))
        elif sort_by == 'latest':
            self.filtered_posts.sort(key=lambda post: post.get('createdAt', ''), reverse=True)

        self.current_post_index = 0  # Reset the current post index
        self.clear_posts()  # Clear existing posts
        self.display_bluesky_posts()  # Display the newly sorted posts

    def generate_pastel_colors(self, n):
        colors = []
        for i in range(n):
            hue = i / n
            saturation = random.uniform(0.3, 0.7)
            lightness = random.uniform(0.8, 0.9)
            r, g, b = colorsys.hls_to_rgb(hue, lightness, saturation)
            colors.append(f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}")
        return colors

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("CAR files", "*.car")])
        if filename:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, filename)
            self.start_loading(filename)

    def start_loading(self, file_path):
        self.clear_posts()
        self.progress_bar.grid()
        self.progress_bar.set(0)
        threading.Thread(target=self.load_car_file, args=(file_path,), daemon=True).start()

    def search_car_file(self, query):
        wildcard_pattern = self.wildcard_to_regex(query)
        matched_posts = []

        for post in self.bluesky_posts:
            if self.match_post(post, wildcard_pattern, query):
                matched_posts.append(post)

        return matched_posts

    def wildcard_to_regex(self, query):
        return re.compile(query.replace('*', '.*').replace('?', '.'))

    def match_post(self, post, wildcard_pattern, original_query):
        text = post['text'].lower()
        author = post['author'].lower()

        # Exact match
        if wildcard_pattern.search(text) or wildcard_pattern.search(author):
            return True

        # Fuzzy matching for misspellings and near terms
        if self.fuzzy_match(text, original_query) or self.fuzzy_match(author, original_query):
            return True

        return False

    def fuzzy_match(self, text, query, threshold=80):
        words = text.split()
        for word in words:
            if fuzz.ratio(word, query) >= threshold:
                return True
        return False

    def load_car_file(self, file_path):
        self.bluesky_posts = []
        try:
            with open(file_path, 'rb') as f:
                f.seek(0, 2)
                file_size = f.tell()
                f.seek(0)

                header_length = safe_varint_decode(f)
                f.read(header_length)  # Skip header

                while f.tell() < file_size:
                    try:
                        block_length = safe_varint_decode(f)
                        if block_length == 0:
                            break

                        cid_bytes = self.read_cid(f)
                        cid = CID.decode(cid_bytes)

                        data_length = block_length - len(cid_bytes)
                        block_data = f.read(data_length)

                        block_info = self.process_block(block_data, cid)
                        if block_info:
                            self.bluesky_posts.append(block_info)

                        progress = f.tell() / file_size
                        self.update_progress(progress)

                    except EOFError:
                        break
                    except Exception:
                        continue

            self.filtered_posts = self.bluesky_posts
            self.after(0, self.display_bluesky_posts)

        except Exception as e:
            self.after(0, self.show_error, f"Error loading CAR file: {e}")

        finally:
            self.after(0, self.progress_bar.grid_remove)

    def update_progress(self, value):
        self.after(0, self.progress_bar.set, value)

    def clear_posts(self):
        for widget in self.posts_frame.winfo_children():
            widget.destroy()
        self.current_post_index = 0

    def display_bluesky_posts(self):
        self.load_more_posts()

    def load_more_posts(self):
        end_index = min(self.current_post_index + self.posts_per_page, len(self.filtered_posts))
        for i, post in enumerate(self.filtered_posts[self.current_post_index:end_index], start=self.current_post_index):
            color_index = i % len(self.pastel_colors)
            post_frame = ctk.CTkFrame(self.posts_frame, fg_color=self.pastel_colors[color_index], corner_radius=10)
            post_frame.grid(sticky="ew", padx=10, pady=5)
            post_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(post_frame, text=f"Author: {post['author']}", anchor="w", text_color="#1E3A8A").grid(sticky="ew", padx=5, pady=2)
            ctk.CTkLabel(post_frame, text=f"Created At: {post['createdAt']}", anchor="w", text_color="#4B5563").grid(sticky="ew", padx=5, pady=2)
            ctk.CTkLabel(post_frame, text=f"Text: {post['text']}", anchor="w", wraplength=800, text_color="#1F2937").grid(sticky="ew", padx=5, pady=2)

        self.current_post_index = end_index

    def on_mousewheel(self, event):
        if self.posts_frame.winfo_height() < self.posts_frame._parent_canvas.winfo_height():
            return

        canvas = self.posts_frame._parent_canvas
        if canvas.yview() == (0.0, 1.0):
            return

        # Increase the scrolling speed significantly
        scroll_speed_multiplier = 20
        delta = int(-1 * (event.delta / 60) * scroll_speed_multiplier)

        # Add a minimum scroll amount to ensure fast scrolling even with small mouse movements
        min_scroll = 10 if event.delta < 0 else -10
        delta = max(delta, min_scroll) if event.delta < 0 else min(delta, min_scroll)

        if event.delta < 0 and canvas.yview()[1] >= 0.9:  # Scrolling down and near the bottom
            self.load_more_posts()

        canvas.yview_scroll(delta, "units")

    def perform_search(self, event=None):
        search_query = self.search_entry.get().strip().lower()
        if search_query:
            self.filtered_posts = self.search_car_file(search_query)
        else:
            self.filtered_posts = self.bluesky_posts
        self.clear_posts()
        self.display_bluesky_posts()

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
            return None
        except Exception:
            return None

    def read_cid(self, file):
        first_byte = file.read(1)
        if first_byte == b'\x12':
            if file.read(1) != b'\x20':
                raise ValueError("Invalid CIDv0")
            return b'\x12\x20' + file.read(32)
        else:
            file.seek(-1, 1)
            version = safe_varint_decode(file)
            if version != 1:
                raise ValueError(f"Unsupported CID version: {version}")
            codec = safe_varint_decode(file)
            mh_code = safe_varint_decode(file)
            mh_length = safe_varint_decode(file)
            mh_digest = file.read(mh_length)
            return varint.encode(version) + varint.encode(codec) + varint.encode(mh_code) + varint.encode(mh_length) + mh_digest

    def show_error(self, message):
        error_label = ctk.CTkLabel(self.posts_frame, text=message, text_color="red")
        error_label.grid(sticky="ew", padx=10, pady=5)

if __name__ == "__main__":
    app = CARFileReader()
    app.mainloop()