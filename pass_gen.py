import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import random
import string
import json
import os
import sqlite3
import bcrypt
from cryptography.fernet import Fernet

# Generate or load encryption key
if not os.path.exists("secret.key"):
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
else:
    with open("secret.key", "rb") as key_file:
        key = key_file.read()

cipher_suite = Fernet(key)

# Database Setup
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
""")
conn.commit()

# Authentication Functions
def register_user():
    username = username_entry.get()
    password = password_entry.get()
    if not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "Registration successful! Please log in.")
        register_window.destroy()
        show_login()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")

def login_user():
    username = username_entry.get()
    password = password_entry.get()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    if result and bcrypt.checkpw(password.encode(), result[0]):
        messagebox.showinfo("Success", "Login successful!")
        login_window.destroy()
        open_main_app()
    else:
        messagebox.showerror("Error", "Invalid username or password!")

# GUI for Login & Register
def show_login():
    global login_window, username_entry, password_entry
    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("300x250")
    login_window.configure(bg="#ecf0f1")
    tk.Label(login_window, text="Username:", bg="#ecf0f1", fg="#2c3e50", font=("Arial", 12)).pack()
    username_entry = tk.Entry(login_window, font=("Arial", 12))
    username_entry.pack()
    tk.Label(login_window, text="Password:", bg="#ecf0f1", fg="#2c3e50", font=("Arial", 12)).pack()
    password_entry = tk.Entry(login_window, show="*", font=("Arial", 12))
    password_entry.pack()
    tk.Button(login_window, text="Login", command=login_user, font=("Arial", 12, "bold"), bg="#3498db", fg="white").pack(pady=10)
    tk.Button(login_window, text="Register", command=show_register, font=("Arial", 12, "bold"), bg="#2c3e50", fg="white").pack(pady=5)
    login_window.mainloop()

def show_register():
    global register_window, username_entry, password_entry
    register_window = tk.Tk()
    register_window.title("Register")
    register_window.geometry("300x250")
    register_window.configure(bg="#ecf0f1")
    tk.Label(register_window, text="Username:", bg="#ecf0f1", fg="#2c3e50", font=("Arial", 12)).pack()
    username_entry = tk.Entry(register_window, font=("Arial", 12))
    username_entry.pack()
    tk.Label(register_window, text="Password:", bg="#ecf0f1", fg="#2c3e50", font=("Arial", 12)).pack()
    password_entry = tk.Entry(register_window, show="*", font=("Arial", 12))
    password_entry.pack()
    tk.Button(register_window, text="Register", command=register_user, font=("Arial", 12, "bold"), bg="#3498db", fg="white").pack(pady=10)

def open_main_app():
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
    import string
    import random
    import json
    from cryptography.fernet import Fernet

    # Encryption Setup
    key = Fernet.generate_key()
    cipher_suite = Fernet(key)

    def generate_password():
        length = int(length_var.get())
        complexity = complexity_var.get()

        if complexity == "Low":
            characters = string.ascii_letters + string.digits
        elif complexity == "Medium":
            characters = string.ascii_letters + string.digits + string.punctuation
        elif complexity == "High":
            characters = string.ascii_letters + string.digits + string.punctuation + string.whitespace

        password = ''.join(random.choice(characters) for _ in range(length))
        password_var.set(password)
        clipboard_copy(password)

    def clipboard_copy(text):
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    def save_password():
        password = password_var.get()
        if not password:
            messagebox.showwarning("Warning", "No password generated!")
            return

        encrypted_password = cipher_suite.encrypt(password.encode()).decode()
        data = {"password": encrypted_password}

        with open("passwords.json", "a") as file:
            json.dump(data, file)
            file.write("\n")

        messagebox.showinfo("Success", "Password saved securely!")

    # Text Editor Functions
    def make_bold():
        try:
            current_tags = text_editor.tag_names("sel.first")
            if "bold" in current_tags:
                text_editor.tag_remove("bold", "sel.first", "sel.last")
                action_stack.append(("remove_bold", text_editor.index("sel.first"), text_editor.index("sel.last")))
            else:
                text_editor.tag_add("bold", "sel.first", "sel.last")
                text_editor.tag_configure("bold", font=("Arial", 12, "bold"))
                action_stack.append(("add_bold", text_editor.index("sel.first"), text_editor.index("sel.last")))
        except tk.TclError:
            messagebox.showwarning("Warning", "No text selected!")

    def make_italic():
        try:
            current_tags = text_editor.tag_names("sel.first")
            if "italic" in current_tags:
                text_editor.tag_remove("italic", "sel.first", "sel.last")
                action_stack.append(("remove_italic", text_editor.index("sel.first"), text_editor.index("sel.last")))
            else:
                text_editor.tag_add("italic", "sel.first", "sel.last")
                text_editor.tag_configure("italic", font=("Arial", 12, "italic"))
                action_stack.append(("add_italic", text_editor.index("sel.first"), text_editor.index("sel.last")))
        except tk.TclError:
            messagebox.showwarning("Warning", "No text selected!")

    def undo_action():
        if not action_stack:
            messagebox.showwarning("Warning", "Nothing to undo!")
            return

        action = action_stack.pop()  # Get the last action
        action_type, start, end = action

        if action_type == "add_bold":
            text_editor.tag_remove("bold", start, end)
        elif action_type == "remove_bold":
            text_editor.tag_add("bold", start, end)
            text_editor.tag_configure("bold", font=("Arial", 12, "bold"))
        elif action_type == "add_italic":
            text_editor.tag_remove("italic", start, end)
        elif action_type == "remove_italic":
            text_editor.tag_add("italic", start, end)
            text_editor.tag_configure("italic", font=("Arial", 12, "italic"))

    root = tk.Tk()
    root.title("Secure Password Generator & Editor")
    root.geometry("800x600")

    # Applying professional theme
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TFrame", background="#2C3E50")
    style.configure("TLabel", background="#2C3E50", foreground="white", font=("Arial", 10))
    style.configure("TButton", background="#1ABC9C", foreground="black", font=("Arial", 10, "bold"))
    style.configure("TEntry", fieldbackground="#ECF0F1", font=("Arial", 10))
    style.configure("TCombobox", fieldbackground="#ECF0F1", font=("Arial", 10))

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    password_tab = ttk.Frame(notebook)
    notebook.add(password_tab, text="Password Generator")

    password_frame = ttk.Frame(password_tab, padding=20, relief="ridge", borderwidth=2)
    password_frame.place(relx=0.5, rely=0.4, anchor="center")

    length_label = ttk.Label(password_frame, text="Password Length:")
    length_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

    length_var = tk.IntVar(value=12)
    length_entry = ttk.Entry(password_frame, textvariable=length_var, width=10)
    length_entry.grid(row=0, column=1, padx=10, pady=5)

    complexity_label = ttk.Label(password_frame, text="Complexity:")
    complexity_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

    complexity_var = tk.StringVar(value="Medium")
    complexity_combobox = ttk.Combobox(password_frame, textvariable=complexity_var, values=["Low", "Medium", "High"], width=8)
    complexity_combobox.grid(row=1, column=1, padx=10, pady=5)

    generate_button = ttk.Button(password_frame, text="Generate Password", command=generate_password)
    generate_button.grid(row=2, column=0, columnspan=2, pady=10, ipadx=20)

    password_var = tk.StringVar()
    password_entry = ttk.Entry(password_frame, textvariable=password_var, state="readonly", width=25)
    password_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    save_button = ttk.Button(password_frame, text="Save Password", command=save_password)
    save_button.grid(row=4, column=0, columnspan=2, pady=10, ipadx=20)

    text_tab = ttk.Frame(notebook)
    notebook.add(text_tab, text="Text Editor")

    # Enable undo functionality in the text editor
    text_editor = scrolledtext.ScrolledText(text_tab, wrap=tk.WORD, undo=True, font=("Arial", 12))
    text_editor.pack(fill="both", expand=True, padx=10, pady=10)

    button_frame = ttk.Frame(text_tab)
    button_frame.pack(pady=5)

    bold_button = ttk.Button(button_frame, text="Bold", command=make_bold)
    bold_button.pack(side="left", padx=5)

    italic_button = ttk.Button(button_frame, text="Italic", command=make_italic)
    italic_button.pack(side="left", padx=5)

    undo_button = ttk.Button(button_frame, text="Undo", command=undo_action)
    undo_button.pack(side="left", padx=5)

    # Stack to track actions
    action_stack = []

    root.mainloop()

if __name__ == "__main__":
    show_login()