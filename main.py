from tkinter import *
from tkinter import messagebox
import base64


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

def save_and_encrypt_data():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    master_encrypted = master_encrypted_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_encrypted) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        #encryption
        message_encrypted = encode(master_encrypted, message)
        try:
            with open("myencrypted.txt","a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("myencrypted.txt","w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            master_encrypted_input.delete(0, END)
            input_text.delete("1.0", END)

def decrpyt_data():
    message_encrypted = input_text.get("1.0", END)
    master_encrypted = master_encrypted_input.get()

    if len(master_encrypted) == 0 or len(master_encrypted) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            decrypted_message = decode(master_encrypted, message_encrypted)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")






#UI,
FONT = ("Verdana", 12, "bold")
window = Tk()
window.title("Encrypted Data")
window.config(padx=30, pady=30)

photo = PhotoImage(file="encrypted2.png")
photo_label = Label(image=photo)
photo_label.pack()

#canvas = Canvas(height=200, width=200)
#canvas.create_image(100,100, image=photo)
#canvas.pack()

title_info_label = Label(text="Enter Your Title", font=FONT)
title_info_label.pack()


title_entry = Entry(width=40)
title_entry.pack()

input_info_label = Label(text="Enter Your Data", font=FONT)
input_info_label.pack()

input_text = Text(width=35, height=15)
input_text.pack()

master_encrypted_label = Label(text="Enter Master Key", font=FONT)
master_encrypted_label.pack()

master_encrypted_input = Entry(width=40)
master_encrypted_input.pack()

save_button = Button(text="Save & Encrypt", command=save_and_encrypt_data)
save_button.pack()

decrypt_button = Button(text="Decrypt", command=decrpyt_data)
decrypt_button.pack()



window.mainloop()