import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from cryptography.fernet import Fernet
import os


# ==========================
#  ENCRYPTION KEY HANDLING
# ==========================

KEY_FILE = "secret.key"

def load_key():
    """Load or generate encryption key."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key


fernet = Fernet(load_key())


# ==========================
#  DATABASE SETUP
# ==========================

DB = "passwords.db"

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        );
    """)
    conn.commit()
    conn.close()


def add_entry(service, username, password):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    encrypted = fernet.encrypt(password.encode())
    cur.execute("INSERT INTO passwords(service, username, password) VALUES (?, ?, ?)",
                (service, username, encrypted))
    conn.commit()
    conn.close()


def get_all_entries():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, service, username, password FROM passwords")
    rows = cur.fetchall()
    conn.close()
    return rows


def update_entry(entry_id, service, username, password):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    encrypted = fernet.encrypt(password.encode())
    cur.execute("""
        UPDATE passwords
        SET service = ?, username = ?, password = ?
        WHERE id = ?
    """, (service, username, encrypted, entry_id))
    conn.commit()
    conn.close()


def delete_entry(entry_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()

    # Renumber remaining IDs
    renumber_ids()

def renumber_ids():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    # Get all data sorted by old ID
    cur.execute("SELECT service, username, password FROM passwords ORDER BY id")
    rows = cur.fetchall()

    # Drop and recreate the table
    cur.execute("DROP TABLE IF EXISTS passwords")
    cur.execute("""
        CREATE TABLE passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        );
    """)

    # Reinsert everything with new IDs
    new_id = 1
    for service, username, password in rows:
        cur.execute(
            "INSERT INTO passwords (id, service, username, password) VALUES (?, ?, ?, ?)",
            (new_id, service, username, password)
        )
        new_id += 1

    conn.commit()
    conn.close()

# ==========================
#  GUI APPLICATION
# ==========================

class PasswordManager:
    def __init__(self, root):
        self.root = root
        root.title("Personal Password Manager")
        root.geometry("600x400")

        # List widget
        self.tree = ttk.Treeview(root, columns=("ID", "Service", "Username"), show="headings")
        self.tree.heading("ID", text="ID")
        self.tree.heading("Service", text="Service")
        self.tree.heading("Username", text="Username")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Buttons
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="Add Entry", command=self.add_window).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="View Password", command=self.view_password).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Update Entry", command=self.update_window).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="Delete Entry", command=self.delete_selected).grid(row=0, column=3, padx=5)

        self.refresh()

    # ---- UI Helpers ----

    def refresh(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for row in get_all_entries():
            self.tree.insert("", tk.END, values=(row[0], row[1], row[2]))

    def get_selected_id(self):
        selected = self.tree.focus()
        if not selected:
            return None
        return self.tree.item(selected)["values"][0]

    # ---- Feature Windows ----

    def add_window(self):
        win = tk.Toplevel(self.root)
        win.title("Add Password")
        tk.Label(win, text="Service").grid(row=0, column=0)
        tk.Label(win, text="Username").grid(row=1, column=0)
        tk.Label(win, text="Password").grid(row=2, column=0)

        e_service = tk.Entry(win)
        e_username = tk.Entry(win)
        e_password = tk.Entry(win, show="*")
        e_service.grid(row=0, column=1)
        e_username.grid(row=1, column=1)
        e_password.grid(row=2, column=1)

        def save():
            add_entry(e_service.get(), e_username.get(), e_password.get())
            self.refresh()
            win.destroy()

        tk.Button(win, text="Save", command=save).grid(row=3, column=0, columnspan=2)

    def view_password(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showwarning("Error", "No entry selected")
            return

        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cur.execute("SELECT password FROM passwords WHERE id = ?", (entry_id,))
        encrypted = cur.fetchone()[0]
        conn.close()

        decrypted = fernet.decrypt(encrypted).decode()
        messagebox.showinfo("Password", f"Password: {decrypted}")

    def update_window(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showwarning("Error", "No entry selected")
            return

        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        cur.execute("SELECT service, username, password FROM passwords WHERE id = ?", (entry_id,))
        service, username, encrypted = cur.fetchone()
        conn.close()

        old_password = fernet.decrypt(encrypted).decode()

        # update window
        win = tk.Toplevel(self.root)
        win.title("Update Entry")

        tk.Label(win, text="Service").grid(row=0, column=0)
        tk.Label(win, text="Username").grid(row=1, column=0)
        tk.Label(win, text="Password").grid(row=2, column=0)

        e_service = tk.Entry(win)
        e_username = tk.Entry(win)
        e_password = tk.Entry(win, show="*")
        e_service.insert(0, service)
        e_username.insert(0, username)
        e_password.insert(0, old_password)
        e_service.grid(row=0, column=1)
        e_username.grid(row=1, column=1)
        e_password.grid(row=2, column=1)

        def save():
            update_entry(entry_id, e_service.get(), e_username.get(), e_password.get())
            self.refresh()
            win.destroy()

        tk.Button(win, text="Save Changes", command=save).grid(row=3, column=0, columnspan=2)

    def delete_selected(self):
        entry_id = self.get_selected_id()
        if entry_id is None:
            messagebox.showwarning("Error", "No entry selected")
            return

        if messagebox.askyesno("Confirm", "Delete this entry?"):
            delete_entry(entry_id)
            self.refresh()
    
    


# ==========================
#  RUN APPLICATION
# ==========================

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
