from tkinter import *
import tkinter
from PIL import Image, ImageTk
from tkinter import messagebox
import base64

window = tkinter.Tk()
window.config(width=350, height=600)
window.config(padx=40, pady=40)
window.title("Secret Notes")

#defs
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def save_and_encrypt():
    title = title_entry.get()
    message = secret_msg.get("1.0", END)
    mainkey = masterKey.get()

    if len(title) == 0 or len(message) == 0 or len(mainkey) == 0:
        messagebox.showinfo(title="Error", message="Please enter all info")
    else:
        #encryption
        message_enc = encode(mainkey, message)
        try:
            with open("mysecretnotes.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_enc}")
        except FileNotFoundError:
            with open("mysecretnotes.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_enc}")
        finally:
            title_entry.delete(0, END)
            secret_msg.delete("1.0", END)
            masterKey.delete(0, END)

def decrypt_notes():
    msg_encrypted = secret_msg.get("1.0", END)
    theKey = masterKey.get()

    if len(msg_encrypted) == 0 or len(theKey) == 0:
        messagebox.showinfo(title="Error", message="Please enter all info")
    else:
        try:
            decrypted_message = decode(theKey, msg_encrypted)
            secret_msg.delete("1.0", END)
            secret_msg.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error", message="please enter encrypted message!")


#interface
lb_one = tkinter.Label(text="Enter your title")
lb_one.pack(pady=3)

title_entry = tkinter.Entry(width=40)
title_entry.pack(pady=3)

lb_two = tkinter.Label(text="Enter your secret")
lb_two.pack(pady=3)

secret_msg = tkinter.Text(width=30, height=20)
secret_msg.pack(pady=3)

lb_three = tkinter.Label(text="Enter your key")
lb_three.pack(pady=3)

masterKey = tkinter.Entry(width=40)
masterKey.pack(pady=3)

#buttons
button1 = tkinter.Button(text="Save end Encrypt", command=save_and_encrypt)
button1.pack(pady=3)

button2 = tkinter.Button(text="Decrypt", command=decrypt_notes)
button2.pack()


window.mainloop()
