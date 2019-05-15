from Client import encryptFile, decryptFile
from tkinter import *
import tkFileDialog
import os

class ClientGUI:

    def __init__(self, master):
        self.master = master
        master.minsize(500,300)
        master.geometry("600x300")
        master.title("Client")

        self.clearLabel = Label(master, text="Select file to protect:")
        self.clearLabel.place(x=80, y=30)

        self.encLabel = Label(master, text="Select encrypted file name:")
        self.encLabel.place(x=80, y=80)

        self.decLabel = Label(master, text="Select decrypted file name:")
        self.decLabel.place(x=80, y=130)

        self.browseButton = Button(master, text='Browse', command=self.askopenfile)
        self.browseButton.place(x=500, y=27)

        self.clearVar = StringVar()
        self.clearTextBox = Entry(master, textvariable=self.clearVar, width=40)
        self.clearTextBox.focus_set()
        self.clearTextBox.place(x=250, y=30)
        self.clearVar.set("clear_file.txt")

        encVar = StringVar()
        self.encTextBox = Entry(master, textvariable=encVar, width=40)
        self.encTextBox.place(x=250, y=80)
        encVar.set("enc_file.txt")

        decVar = StringVar()
        self.decTextBox = Entry(master, textvariable=decVar, width=40)
        self.decTextBox.place(x=250, y=130)
        decVar.set("dec_file.txt")

        self.encryptButton = Button(master, text="Encrypt", command=self.encrypt, height=3, width=20, bg="red")
        self.encryptButton.place(x=100, y=200)

        self.decryptButton = Button(master, text="Decrypt", command=self.decrypt, height=3, width=20, bg="green")
        self.decryptButton.place(x=350, y=200)

    def toast(self, message):
        toplevel = Toplevel()
        label1 = Label(toplevel, text=message, height=0, width=30)
        label1.pack()
        label2 = Label(toplevel, text="Please wait!", height=0, width=30)
        label2.pack()
        toplevel.grab_set()
        return toplevel

    def encrypt(self):
        self.clearFile = self.clearTextBox.get()
        self.encFile = self.encTextBox.get()
        self.decFile = self.decTextBox.get()
        if encryptFile(self.clearFile, self.encFile) is not None:
            self.toast("[ERROR] Cannot encrypt given file!")
        else:
            cmd = "start "+self.encFile
            os.system(cmd)

    def decrypt(self):
        if decryptFile(self.encFile, self.decFile) is not None:
            self.toast("[ERROR] Cannot decrypt given file!")
        cmd = "start "+self.decFile
        os.system(cmd)

    def askopenfile(self):
        filename = tkFileDialog.askopenfile(mode='rb',title='Choose a file')
        if filename is not None:
            filename = str.split(str(filename),"'")[1]
            k = filename.rfind("/")
            k2 = filename.rfind(".")
            self.clearTextBox.delete(0, END)
            self.clearTextBox.insert(0, filename)
            self.encTextBox.delete(0, END)
            self.encTextBox.insert(0, filename[:k]+"/enc_"+filename[k+1:k2]+".txt")
            self.decTextBox.delete(0, END)
            self.decTextBox.insert(0, filename[:k]+"/dec_"+filename[k+1:])
