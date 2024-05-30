import os
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import json


class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bezpieczna Komunikacja")

        self.setup_ui()

        self.keys = {}  # słownik przechowujący klucze
        self.messages_keys = {}  # słownik przechowujący powiązania wiadomości z kluczami
        self.current_key = None
        self.cipher_suite = None
        self.load_keys_from_file()  # wczytanie kluczy z pliku

    def setup_ui(self):

        self.root.config(bg="#f0f0f0")  # Ustawienie koloru tła głównego okna

        # Główny kontener
        main_frame = tk.Frame(self.root, bg="#f0f0f0")
        main_frame.pack(padx=20, pady=20)

        # Etykieta "Wpisz wiadomość"
        self.mode_label = tk.Label(main_frame, text="Wpisz wiadomość:", font=("Helvetica", 14), bg="#f0f0f0")
        self.mode_label.grid(row=0, column=0, pady=10, sticky="w")

        # Pole do wprowadzania wiadomości
        self.message_entry = tk.Entry(main_frame, width=50, font=("Helvetica", 12), bd=2)
        self.message_entry.grid(row=1, column=0, pady=5)
        self.message_entry.config(highlightthickness=2)  # Dodanie obramowania dla lepszego wyglądu

        # Przycisk "Wyślij"
        self.send_button = tk.Button(main_frame, text="Wyślij", command=self.send_message,
                                     font=("Helvetica", 12, "bold"),
                                     bg="#007bff", fg="white", relief="flat", padx=15, pady=5)
        self.send_button.grid(row=2, column=0, pady=15)
        self.send_button.bind("<Enter>", lambda event: self.on_enter(event, self.send_button, "#0056b3"))
        self.send_button.bind("<Leave>", lambda event: self.on_leave(event, self.send_button, "#007bff"))

        # Etykieta "Odebrane wiadomości"
        self.receive_label = tk.Label(main_frame, text="Odebrane wiadomości:", font=("Helvetica", 14), bg="#f0f0f0")
        self.receive_label.grid(row=3, column=0, pady=10, sticky="w")

        # Pole tekstowe do wyświetlania odebranych wiadomości
        self.receive_text = tk.Text(main_frame, height=10, width=50, font=("Helvetica", 12))
        self.receive_text.grid(row=4, column=0, pady=5)

        # Przycisk "Generuj nowy klucz"
        self.generate_key_button = tk.Button(main_frame, text="Generuj nowy klucz", command=self.generate_key,
                                             font=("Helvetica", 12, "bold"), bg="#28a745", fg="white", relief="flat",
                                             padx=15, pady=5)
        self.generate_key_button.grid(row=5, column=0, pady=15)
        self.generate_key_button.bind("<Enter>",
                                      lambda event: self.on_enter(event, self.generate_key_button, "#218838"))
        self.generate_key_button.bind("<Leave>",
                                      lambda event: self.on_leave(event, self.generate_key_button, "#28a745"))

        # Przycisk "Wczytaj klucz z pliku"
        self.load_key_button = tk.Button(main_frame, text="Wczytaj klucz z pliku", command=self.load_key,
                                         font=("Helvetica", 12, "bold"), bg="#ffc107", fg="white", relief="flat",
                                         padx=15, pady=5)
        self.load_key_button.grid(row=6, column=0, pady=5)
        self.load_key_button.bind("<Enter>", lambda event: self.on_enter(event, self.load_key_button, "#d39e00"))
        self.load_key_button.bind("<Leave>", lambda event: self.on_leave(event, self.load_key_button, "#ffc107"))

        # Przycisk "Odczytaj zaszyfrowaną wiadomość"
        self.read_message_button = tk.Button(main_frame, text="Odczytaj zaszyfrowaną wiadomość",
                                             command=self.read_message, font=("Helvetica", 12, "bold"), bg="#dc3545",
                                             fg="white", relief="flat", padx=15, pady=5)
        self.read_message_button.grid(row=7, column=0, pady=5)
        self.read_message_button.bind("<Enter>",
                                      lambda event: self.on_enter(event, self.read_message_button, "#c82333"))
        self.read_message_button.bind("<Leave>",
                                      lambda event: self.on_leave(event, self.read_message_button, "#dc3545"))

    def on_enter(self, event, widget, color):
        widget.config(bg=color)

    def on_leave(self, event, widget, color):
        widget.config(bg=color)

    def save_keys_to_file(self):
        documents_dir = os.path.join(os.path.expanduser('~'), 'Documents')
        audyt_dir = os.path.join(documents_dir, 'audyt')

        # Jeśli folder audyt nie istnieje, utwórz go
        if not os.path.exists(audyt_dir):
            os.makedirs(audyt_dir)

        keys_file_path = os.path.join(audyt_dir, "keys.json")
        messages_keys_file_path = os.path.join(audyt_dir, "messages_keys.json")

        # Zapisujemy ścieżki jako względne do katalogu audytowego
        relative_messages_keys = {os.path.relpath(k, audyt_dir): base64.b64encode(v).decode('utf-8') for k, v in
                                  self.messages_keys.items()}

        with open(keys_file_path, "w") as keys_file:
            json.dump({k: base64.b64encode(v).decode('utf-8') for k, v in self.keys.items()}, keys_file)

        with open(messages_keys_file_path, "w") as messages_keys_file:
            json.dump(relative_messages_keys, messages_keys_file)

    def load_keys_from_file(self):
        documents_dir = os.path.join(os.path.expanduser('~'), 'Documents')
        audyt_dir = os.path.join(documents_dir, 'audyt')

        # Jeśli folder audyt nie istnieje, utwórz go
        if not os.path.exists(audyt_dir):
            os.makedirs(audyt_dir)

        keys_file_path = os.path.join(audyt_dir, "keys.json")
        messages_keys_file_path = os.path.join(audyt_dir, "messages_keys.json")

        if os.path.exists(keys_file_path):
            with open(keys_file_path, "r") as keys_file:
                self.keys = {k: base64.b64decode(v) for k, v in json.load(keys_file).items()}

        if os.path.exists(messages_keys_file_path):
            with open(messages_keys_file_path, "r") as messages_keys_file:
                relative_messages_keys = json.load(messages_keys_file)
                self.messages_keys = {os.path.join(audyt_dir, k): base64.b64decode(v) for k, v in
                                      relative_messages_keys.items()}

    def send_message(self):
        if not self.current_key or not self.cipher_suite:
            messagebox.showwarning("Błąd", "Najpierw wczytaj klucz.")
            return

        message = self.message_entry.get()
        if not message:  # Sprawdzenie, czy pole wiadomości nie jest puste
            messagebox.showwarning("Błąd", "Wpisz treść wiadomości przed wysłaniem.")
            return

        encrypted_message = self.encrypt_message(message)

        # Domyślne zapisywanie zaszyfrowanej wiadomości do folderu Documents/audyt
        default_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'audyt')
        file_path = filedialog.asksaveasfilename(initialdir=default_dir, defaultextension=".txt",
                                                 filetypes=[("Plik tekstowy", "*.txt")])

        if not file_path:  # Jeśli użytkownik anuluje wybór pliku
            return

        with open(file_path, "wb") as file:
            file.write(encrypted_message)

        # Dodaj klucz do słownika powiązań wiadomości z kluczem
        self.messages_keys[file_path] = self.current_key

        # Zapisz powiązania wiadomości z kluczami do pliku
        self.save_keys_to_file()

        self.message_entry.delete(0, tk.END)

        messagebox.showinfo("Sukces",
                            "Wiadomość została zaszyfrowana i zapisana.")
    def encrypt_message(self, message):
        return self.cipher_suite.encrypt(message.encode())

    def decrypt_message(self, encrypted_message, key):
        cipher_suite = Fernet(key)
        return cipher_suite.decrypt(encrypted_message).decode()

    def generate_key(self):
        # Funkcja stylująca okna dialogowe
        def style_dialog(dialog):
            dialog.configure(bg="#f0f0f0")  # Kolor tła
            dialog.attributes("-alpha", 0.95)  # Przezroczystość
            dialog.resizable(False, False)  # Blokowanie zmiany rozmiaru

        # Funkcja stylująca etykiety
        def style_label(parent, text):
            label = tk.Label(parent, text=text, bg="#f0f0f0", font=("Helvetica", 12))
            return label

        # Funkcja stylująca pola wprowadzania
        def style_entry(parent, show=None):
            entry = tk.Entry(parent, show=show, bg="white", font=("Helvetica", 12), borderwidth=1, relief="solid")
            return entry

        # Funkcja otwierająca okno dialogowe do wprowadzania hasła
        def open_password_dialog():
            key_name = key_entry.get()
            key_dialog.destroy()  # Zamknięcie okna dialogowego z nazwą klucza

            # Okno dialogowe do wprowadzania hasła
            password_dialog = tk.Toplevel(self.root)
            password_dialog.title("Generowanie klucza")
            style_dialog(password_dialog)

            # Obliczenie pozycji okna dialogowego na środku ekranu
            x = (screen_width - dialog_width) // 2
            y = (screen_height - dialog_height) // 2
            password_dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")

            # Etykieta i pole wprowadzania hasła
            password_label = style_label(password_dialog, "Podaj hasło do klucza:")
            password_label.pack(padx=5, pady=5)

            password_entry = style_entry(password_dialog, show="*")
            password_entry.pack(padx=5, pady=5)

            # Funkcja generująca i zapisująca klucz
            def generate_and_save_key():
                password = password_entry.get()
                salt = b'salt_'  # Dodanie soli dla zwiększenia bezpieczeństwa

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    salt=salt,
                    iterations=100000,
                    length=32,
                    backend=default_backend()
                )

                derived_key = kdf.derive(password.encode())
                key = base64.urlsafe_b64encode(derived_key)
                self.keys[key_name] = key

                desktop_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'audyt')

                # Utworzenie folderu audyt, jeśli nie istnieje
                if not os.path.exists(desktop_dir):
                    os.makedirs(desktop_dir)

                file_path = os.path.join(desktop_dir, f"{key_name}.key")
                with open(file_path, "wb") as file:
                    file.write(key)

                messagebox.showinfo("Sukces",
                                    "Klucz został wygenerowany")
                self.save_keys_to_file()
                password_dialog.destroy()

            # Przycisk generujący i zapisujący klucz
            generate_button = tk.Button(password_dialog, text="Generuj i Zapisz", command=generate_and_save_key,
                                        bg="#28a745", fg="white", relief="flat", padx=10, pady=5,
                                        font=("Helvetica", 10, "bold"))
            generate_button.pack(padx=5, pady=5)

        # Okno dialogowe do wprowadzania nazwy klucza
        key_dialog = tk.Toplevel(self.root)
        key_dialog.title("Generowanie klucza")
        style_dialog(key_dialog)

        # Obliczenie pozycji okna dialogowego na środku ekranu
        screen_width = key_dialog.winfo_screenwidth()
        screen_height = key_dialog.winfo_screenheight()
        dialog_width = 300
        dialog_height = 100
        x = (screen_width - dialog_width) // 2
        y = (screen_height - dialog_height) // 2
        key_dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")

        # Etykieta i pole wprowadzania nazwy klucza
        key_label = style_label(key_dialog, "Podaj nazwę klucza:")
        key_label.pack(padx=5, pady=5)

        key_entry = style_entry(key_dialog)
        key_entry.pack(padx=5, pady=5)

        # Przycisk otwierający okno dialogowe do wprowadzania hasła
        next_button = tk.Button(key_dialog, text="Dalej", command=open_password_dialog,
                                bg="#007bff", fg="white", relief="flat", padx=10, pady=5,
                                font=("Helvetica", 10, "bold"))
        next_button.pack(padx=5, pady=5)

        key_dialog.mainloop()

    def load_key(self):
        default_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'audyt')
        file_path = filedialog.askopenfilename(initialdir=default_dir, defaultextension=".key",
                                               filetypes=[("Klucz szyfrowania", "*.key")])
        if file_path:
            with open(file_path, "rb") as file:
                self.current_key = file.read()
            self.cipher_suite = Fernet(self.current_key)
            messagebox.showinfo("Sukces", "Klucz został wczytany z pliku.")

            # Znajdź wszystkie pliki wiadomości, które pasują do tego klucza
            for message_file, key in self.messages_keys.items():
                if key == self.current_key:
                    # Jeśli klucz pasuje, ustaw aktualny klucz i zakończ pętlę
                    self.current_message_file = message_file
                    break

            self.save_keys_to_file()

    def read_message(self):
        default_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'audyt')
        file_path = filedialog.askopenfilename(initialdir=default_dir, filetypes=[("Plik tekstowy", "*.txt")])
        if file_path:
            # Normalizacja ścieżki do postaci absolutnej
            absolute_file_path = os.path.abspath(file_path)

            # Szukanie klucza dla znormalizowanej ścieżki
            key = None
            for stored_file_path, stored_key in self.messages_keys.items():
                if os.path.abspath(stored_file_path) == absolute_file_path:
                    key = stored_key
                    break

            if not key:
                messagebox.showerror("Błąd", "Nie znaleziono klucza dla tej wiadomości.")
                return

            # Funkcja stylująca okno dialogowe
            def style_dialog(dialog):
                dialog.configure(bg="#f0f0f0")  # Kolor tła
                dialog.attributes("-alpha", 0.95)  # Przezroczystość
                dialog.resizable(False, False)  # Blokowanie zmiany rozmiaru

            # Funkcja stylująca etykiety
            def style_label(parent, text):
                label = tk.Label(parent, text=text, bg="#f0f0f0", font=("Helvetica", 12))
                return label

            # Funkcja stylująca pola wprowadzania
            def style_entry(parent, show=None):
                entry = tk.Entry(parent, show=show, bg="white", font=("Helvetica", 12), borderwidth=1, relief="solid")
                return entry

            # Okno dialogowe do wprowadzania hasła
            password_dialog = tk.Toplevel(self.root)
            password_dialog.title("Odczytanie zaszyfrowanej wiadomości")
            style_dialog(password_dialog)

            # Obliczenie pozycji okna dialogowego na środku ekranu
            screen_width = password_dialog.winfo_screenwidth()
            screen_height = password_dialog.winfo_screenheight()
            dialog_width = 300
            dialog_height = 100
            x = (screen_width - dialog_width) // 2
            y = (screen_height - dialog_height) // 2
            password_dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")

            # Etykieta i pole wprowadzania hasła
            password_label = style_label(password_dialog, "Podaj hasło do klucza:")
            password_label.pack(padx=5, pady=5)

            password_entry = style_entry(password_dialog, show="*")
            password_entry.pack(padx=5, pady=5)

            # Funkcja odczytująca i wyświetlająca wiadomość
            def read_and_display_message():
                entered_password = password_entry.get()
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    salt=b'salt_',
                    iterations=100000,
                    length=32,
                    backend=default_backend()
                )
                derived_key = kdf.derive(entered_password.encode())
                expected_key = base64.urlsafe_b64encode(derived_key)

                if key != expected_key:
                    messagebox.showerror("Błąd", "Podane hasło do klucza jest niepoprawne.")
                    password_dialog.destroy()
                    return

                try:
                    with open(file_path, "rb") as file:
                        encrypted_message = file.read()

                    decrypted_message = self.decrypt_message(encrypted_message, key)

                    # Dodajemy otrzymaną wiadomość na górę poprzednio odczytanych wiadomości
                    previous_text = self.receive_text.get("1.0", tk.END)
                    self.receive_text.config(state="normal")
                    self.receive_text.delete(1.0, tk.END)
                    self.receive_text.insert(tk.END, f"{decrypted_message}\n{previous_text}")
                    self.receive_text.config(state="disabled")
                    password_dialog.destroy()
                except Exception as e:
                    messagebox.showerror("Błąd",
                                         "Nie udało się odczytać wiadomości. Podane hasło może być niepoprawne.")
                    password_dialog.destroy()

            # Przycisk odczytujący i wyświetlający wiadomość
            read_button = tk.Button(password_dialog, text="Odczytaj", command=read_and_display_message,
                                    bg="#007bff", fg="white", relief="flat", padx=10, pady=5,
                                    font=("Helvetica", 10, "bold"))
            read_button.pack(padx=5, pady=5)

            password_dialog.mainloop()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()