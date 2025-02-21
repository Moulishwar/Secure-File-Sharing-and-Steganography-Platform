
import numpy as np
import sqlite3
import os
import struct
import string
import random
import cv2
import blowfish
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# web creation
from flask import *
app = Flask(__name__)
app.secret_key = 'any random string'


def encrypt(plaintext, cipher):
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext)
    return ct


def decrypt(data, cipher):

    decryptor = cipher.decryptor()
    decry = decryptor.update(data)
    return decry


def xchaencrypt_file(input_filename, output_filename, cipher):
    with open(input_filename, 'rb') as f:
        plaintext = f.read()

    ciphertext = encrypt(plaintext,  cipher)
    with open(output_filename, 'wb') as f:
        f.write(ciphertext)


def xchadecrypt_file(input_filename, output_filename, cipher):
    with open(input_filename, 'rb') as f:
        ciphertext = f.read()
        print(ciphertext)
    decrypted_data = decrypt(ciphertext, cipher)
    with open(output_filename, 'wb') as f:
        f.write(decrypted_data)


con = sqlite3.connect("store.db")
# con.execute("create table data(userid int primary key,name varchar(500),email varchar(500),password varchar(100))")
# con.execute("delete from data where id=1")
# con.execute("drop table sharing")
# con.execute("drop table sharingtable")
# con.execute("drop table requesttable")
# con.commit()
# con.execute("create table sharing(fileid int primary key,filename varchar(100),userid int,totaluser int,shareuser int)")
# con.execute("create table sharingtable(sharingid int,fileid int,userid int,filename varchar(1000),key text)")
# con.execute("create table  requesttable(userid int, otheruserid int,key text,fileid int,status text)")
# y=con.execute("select * from data").fetchall()
# for k in range(1,10):
#     x=con.execute("select * from data").fetchall()
#     try:
#         v=con.execute("select userid from data order by userid desc limit 1").fetchone()[0]+1
#     except Exception as e:
#         v=1
#     user="user"+str(v)
#     email="user"+str(v)+"@gmail.com"
#     pswd="1"
#     con.execute("insert into data values(?,?,?,?)",(v,user,email,pswd))
#     con.commit()
# encryption and decrytion


def generate_key(length=35):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Function to encrypt data using Blowfish


def sencrypt(password, path, user_id, bufferSize=8):
    cipher = blowfish.Cipher(bytes(str(password), 'ascii'))

    with open("upload/" + path, 'rb') as infile:
        data = infile.read()

    encrypted = b''

    for i in range(0, len(data), bufferSize):
        block = bytearray(data[i:(i + bufferSize)])
        # Padding with null bytes
        padded_block = block.ljust(bufferSize, b'\0')

        # Convert padded_block to bytes before encrypting
        encrypted_block = cipher.encrypt_block(bytes(padded_block))

        encrypted += encrypted_block

    # Save encrypted data to file
    encrypted_filename = user_id + "_" + path
    with open("encrpyt/" + encrypted_filename, 'wb') as outfile:
        outfile.write(encrypted)

    return encrypted_filename


def sdecrypt(password, path, bufferSize=8):
    cipher = blowfish.Cipher(bytes(str(password), 'ascii'))

    with open("encrpyt/" + path, 'rb') as infile:
        text = infile.read()

    decrypted = b''

    for i in range(0, len(text), bufferSize):
        block = bytearray(text[i:(i + bufferSize)])
        decrypted_block = cipher.decrypt_block(block)
        decrypted += decrypted_block

    # Save decrypted data to file
    decrypted_filename = path
    with open("static/decrypt/" + decrypted_filename, 'wb') as outfile:
        outfile.write(decrypted)

    return decrypted_filename


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')


@app.route('/sign', methods=["post"])
def sign():
    user = request.form["user"]
    pswd = request.form["pswd"]
    email = request.form["email"]
    con = sqlite3.connect("store.db")

    con.commit()
    try:
        v = con.execute(
            "select userid from data order by userid desc limit 1").fetchone()[0]+1
    except:
        v = 1

    con.execute("insert into data values(?,?,?,?)", (v, user, email, pswd))
    con.commit()
    return redirect("/")


@app.route('/login', methods=["post"])
def login():
    con = sqlite3.connect("store.db")
    user = request.form["email"]
    pswd = request.form["pswd"]
    v = con.execute(
        "select * from data where email=? and password=?", (user, pswd)).fetchone()
    # v=con.execute("select * from data").fetchall()
    try:
        if (len(v) != 0):
            session["user"] = v
            value = "select count(*) from requesttable where otheruserid=%s and status='not'" % (
                v[0])
            val = con.execute(value).fetchone()
            session["noti"] = val[0]
            return redirect("success")
    except Exception as e:
        print(e)
        return redirect("/")


@app.route('/textsten', methods=["get"])
def textsten():
    user = session["user"]
    con = sqlite3.connect("store.db")
    valu = con.execute("select userid,name from data where userid!=?", ([
        session["user"][0]])).fetchall()
    return render_template("textsten.html", valu=valu)


@app.route('/success', methods=["get"])
def succes():
    user = session["user"]
    return render_template("success.html", user=user[1])


def encode_image(cover_image_path, secret_image_path, output_image_path):
    from PIL import Image
    # Open the cover image and secret image
    cover_image = Image.open(cover_image_path)
    secret_image = Image.open(secret_image_path)

    # Resize the secret image to fit inside the cover image
    secret_image = secret_image.resize(cover_image.size)

    # Convert images to RGB mode
    cover_image = cover_image.convert("RGB")
    secret_image = secret_image.convert("RGB")

    # Extract pixel data from images
    cover_pixels = cover_image.load()
    secret_pixels = secret_image.load()

    # Embed secret image into cover image using LSB replacement
    for x in range(cover_image.width):
        for y in range(cover_image.height):
            cover_pixel = list(cover_pixels[x, y])
            secret_pixel = list(secret_pixels[x, y])

            # Replace least significant bits of cover pixel values with secret pixel values
            for i in range(3):  # R, G, B channels
                cover_pixel[i] = (cover_pixel[i] & 0xFE) | (
                    (secret_pixel[i] >> 7) & 1)  # Replace LSB of cover pixel

            # Update cover image pixel with modified pixel values
            cover_pixels[x, y] = tuple(cover_pixel)

    # Save the modified cover image with the embedded secret image
    cover_image.save(output_image_path)
    print("Image encoded successfully.")


def text_to_binary(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    return binary_text


def encode_text(img, text):

    binary_text = text_to_binary(text)
    # Adding a delimiter to mark the end of the text
    binary_text += '1111111111111110'

    data_index = 0

    img_data = img.flatten()

    for pixel_value in img_data:
        # Encode the text in the least significant bit of each color channel
        img_data[data_index] = int(format(pixel_value, '08b')[
                                   :-1] + binary_text[data_index % len(binary_text)], 2)
        data_index += 1

        # Break if all data is encoded
        if data_index == len(binary_text):
            break

    return img_data.reshape(img.shape)


def normalize_color_spacing(img):
    # Convert image to LAB color space and normalize the values
    lab_img = cv2.cvtColor(img, cv2.COLOR_BGR2LAB)
    lab_img[:, :, 0] = cv2.normalize(
        lab_img[:, :, 0], None, 0, 255, cv2.NORM_MINMAX)
    normalized_img = cv2.cvtColor(lab_img, cv2.COLOR_LAB2BGR)

    return normalized_img


@app.route('/uploadtext', methods=['POST'])
def uploadtext():
    con = sqlite3.connect("store.db")
    if request.method == 'POST':
        f = request.files['coverimage']
        count = request.form["count"]
        print(count)
        sender = session["user"][0]
        user = request.form["user"].split("-")[0]
        # con.execute("delete from sharing ")
        con.commit()
        print("upload/"+f.filename)
        f.save("upload/"+f.filename)
        try:
            v = con.execute(
                "select tid from textstenography order by tid desc limit 1").fetchone()[0] + 1
        except:
            v = 1
        con.execute("insert into textstenography (tid,image,userid,shared) values (?,?,?,?)",
                    (v, 'encoded'+f.filename, sender, user))
        # con.execute("delete from sharing where fileid>1")
        con.commit()
        original_image = cv2.imread("upload/"+f.filename)
        normalized_image = normalize_color_spacing(original_image)
        encoded_image = encode_text(normalized_image, count)

        # Save the encoded image
        cv2.imwrite('upload/encoded'+f.filename, encoded_image)
        return redirect("/textsten")


@app.route('/uploadfile', methods=['POST'])
def uploadfile():
    con = sqlite3.connect("store.db")
    if request.method == 'POST':
        f = request.files['file']
        c = request.files['coverimage']
        count = request.form["count"]
        bal = request.form["bal"]
        # con.execute("delete from sharing ")
        con.commit()
        try:
            v = con.execute(
                "select fileid from sharing order by fileid desc limit 1").fetchone()[0] + 1
        except:
            v = 1
        con.execute("insert into sharing (fileid,filename,userid,totaluser,shareuser) values (?,?,?,?,?)",
                    (v, c.filename.split(".")[0]+f.filename, session["user"][0], count, bal))
        # con.execute("delete from sharing where fileid>1")
        con.commit()
        row = con.execute("select * from sharing").fetchall()
        c.save("upload/"+c.filename)
        f.save("upload/"+f.filename)
        new_filename_f = c.filename.split(".")[0] + f.filename
        f.save("upload/"+new_filename_f)
        valu = con.execute("select userid,name from data where userid!=?", ([
                           session["user"][0]])).fetchall()
        encode_image("upload/"+c.filename, "upload/"+f.filename,
                     "static/col/"+c.filename.split(".")[0]+f.filename)

        return render_template("Acknowledgement.html", name=f.filename, count=int(count), fileid=v, valu=valu, cov="static/col/"+c.filename.split(".")[0]+f.filename)


def generatekey():
    import string
    import random

    # initializing size of string
    N = 35

    # using random.choices()
    # generating random strings
    res = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase +
                                 string.digits, k=N))
    return res


@app.route('/storeuser', methods=['POST'])
def storedata():
    con = sqlite3.connect("store.db")
    id = request.form["fileid"]
    fname = request.form["fname"]
    fileid = dict(request.form)
    import json
    # con.execute("delete from sharingtable ")
    # con.commit()
    for x in fileid:
        if "fileid" != x and 'fname' != x:
            key = generatekey()
            va = fileid[x].split("-")

            import json
            import base64

            # Assuming 'key' is the bytes object you want to serialize

            filename = sencrypt(key, fname, va[1])
            try:
                nonce = os.urandom(8)
                keys = os.urandom(32)
                counter = 0
                full_nonce = struct.pack("<Q", counter) + nonce
                algorithm = algorithms.ChaCha20(keys, full_nonce)
                cipher = Cipher(algorithm, mode=None)
                input_file = fname
                output_file = fname
                filename = xchaencrypt_file(input_file, output_file, cipher)
            except:
                pass

            try:
                v = con.execute(
                    "select sharingid from sharingtable order by sharingid desc limit 1").fetchone()[0] + 1
            except:
                v = 1

            sql_query = "INSERT INTO sharingtable (sharingid, fileid, userid, filename, key) VALUES (?, ?, ?, ?, ?)"
            parameters = (v, id, va[0], filename, key)

            # Now use encoded SQL query and parameters in your execute statement
            con.execute(sql_query, parameters)
            con.commit()

    return redirect("/success")


@app.route('/viewtextsten', methods=['POST', 'GET'])
def viewtextsten():
    print([session["user"][0]])
    con = sqlite3.connect("store.db")
    y = con.execute("select * from textstenography where shared=?",
                    ([session["user"][0]])).fetchall()
    return render_template("viewsharedtext.html", y=y)


def decode_text(img):

    binary_text = ''
    img_data = img.flatten()

    for pixel_value in img_data:
        binary_text += format(pixel_value, '08b')[-1]

        # Check for the delimiter indicating the end of the text
        if binary_text[-16:] == '1111111111111110':
            break

    # Convert binary text to ASCII
    text = ''.join(chr(int(binary_text[i:i+8], 2))
                   for i in range(0, len(binary_text)-16, 8))

    return text


@app.route('/textdecrypt', methods=['POST', 'GET'])
def textdecrypt():
    n = request.args.get("fileid")
    con = sqlite3.connect("store.db")
    y = con.execute("select * from textstenography where tid=?",
                    (n)).fetchone()
    # Load the encoded image (for demonstration purposes)
    print("upload/"+y[1])
    loaded_encoded_image = cv2.imread("upload/"+y[1])

    # Decode the text from the loaded encoded image
    decoded_message_loaded = decode_text(loaded_encoded_image)
    y = con.execute("select * from textstenography where shared=?",
                    ([session["user"][0]])).fetchall()
    return render_template("viewsharedtext.html", y=y, decoded_message_loaded=decoded_message_loaded)


@app.route('/viewshared', methods=['POST', 'GET'])
def viewshared():
    print([session["user"][0]])
    con = sqlite3.connect("store.db")
    y = con.execute("select * from sharingtable where userid=?",
                    ([session["user"][0]])).fetchall()
    vx = []
    print(y)
    for k in y:
        k = list(k)
        val = con.execute("select count(*) from requesttable where fileid=? and userid=?",
                          (k[1], session["user"][0])).fetchall()
        if (val[0][0] != 0):
            n = ""

        else:
            n = "Request"
        k.append(n)
        count = con.execute(
            "select * from sharing  where fileid=?", ([k[1]])).fetchone()
        print(count)
        k.append(count[-1])

        apcount = con.execute("select count(*) from requesttable where fileid=? and userid=? and status!='not'",
                              (k[1], session["user"][0])).fetchone()

        k.append(apcount[0])
        vx.append(k)
    print(vx)
    return render_template("viewshared.html", y=vx)


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.clear()
    import os
    path = "static/decrypt/"
    for file_name in os.listdir(path):
        # construct full file path
        file = path + file_name
        os.remove(file)

    return redirect("/")


@app.route('/requestpermission', methods=['POST', 'GET'])
def requestpermission():
    fileid = request.args.get('fileid')
    trans = request.args.get('trans')
    con = sqlite3.connect("store.db")
    val = con.execute("select userid from sharingtable where fileid=? and userid!=?",
                      (fileid, session["user"][0])).fetchall()
    # con.execute("drop table requesttable")
    # con.execute("create table if not exists requesttable(userid int, otheruserid int,key text,fileid int,status text)")
    for k in val:
        con.execute("insert into requesttable (userid,otheruserid,fileid,status) values (?,?,?,?)",
                    (session['user'][0], k[0], fileid, "not"))

    con.commit()

    return redirect("/viewshared")


@app.route('/checkstatus', methods=['POST', 'GET'])
def checkstatus():
    fileid = request.args.get('fileid')
    con = sqlite3.connect("store.db")
    val = con.execute("select * from requesttable where fileid=? and userid=?",
                      (fileid, session["user"][0])).fetchall()
    count = con.execute(
        "select * from sharing  where fileid=?", ([fileid])).fetchone()
    return render_template("checkstatus.html", val=val, count=count)


@app.route('/notification', methods=['POST', 'GET'])
def notification():
    con = sqlite3.connect("store.db")
    value = "select * from requesttable where otheruserid=%s and status='not'" % (
        session["user"][0])
    val = con.execute(value).fetchall()
    return render_template("notification.html", val=val)


@app.route('/approve', methods=['POST', 'GET'])
def approve():
    con = sqlite3.connect("store.db")
    fileid = request.args.get('fileid')
    createuserid = request.args.get('fileshareuser')
    currentuser = session["user"][0]
    print(fileid, createuserid, currentuser)
    key = con.execute("select key from sharingtable where userid=? and fileid=?",
                      (currentuser, fileid)).fetchone()[0]
    con.execute("update requesttable set key=?,status='approved' where otheruserid=? and userid=? and fileid=?",
                (key, currentuser, createuserid, fileid))
    con.commit()
    value = "select count(*) from requesttable where otheruserid=%s and status='not'" % (
        session["user"][0])
    val = con.execute(value).fetchone()
    session["noti"] = val[0]
    return redirect("/notification")


def decode_image(encoded_image_path, output_image_path):
    from PIL import Image
    # Open the encoded image
    encoded_image = Image.open(encoded_image_path)

    # Create a new image to store the decoded secret image
    decoded_image = Image.new("RGB", encoded_image.size)
    decoded_pixels = decoded_image.load()

    # Extract secret image from encoded image using LSB replacement
    for x in range(encoded_image.width):
        for y in range(encoded_image.height):
            encoded_pixel = list(encoded_image.getpixel((x, y)))
            decoded_pixel = [0, 0, 0]

            # Extract LSBs from encoded pixel to obtain secret pixel values
            for i in range(3):  # R, G, B channels
                # Extract LSB from each channel
                decoded_pixel[i] = encoded_pixel[i] & 1

            # Convert the binary pixel values back to integer values (0 or 255)
            decoded_pixel = [0 if bit == 0 else 255 for bit in decoded_pixel]

            # Update decoded image pixel with secret pixel values
            decoded_pixels[x, y] = tuple(decoded_pixel)

    # Save the decoded secret image
    decoded_image.save(output_image_path)
    print("Image decoded successfully.")


@app.route('/decrypt', methods=['POST', 'GET'])
def decrypt():
    import base64
    con = sqlite3.connect("store.db")
    fileid = request.args.get('fileid')
    print(fileid)
    key = con.execute("select * from sharingtable where userid=? and fileid=?",
                      (session["user"][0], fileid)).fetchone()
    print(key)
    path = sdecrypt(key[4], key[-2])
    try:
        nonce = os.urandom(8)
        key = os.urandom(32)
        counter = 0
        full_nonce = struct.pack("<Q", counter) + nonce
        algorithm = algorithms.ChaCha20(key, full_nonce)
        cipher = Cipher(algorithm, mode=None)
        deoutput_file = fileid
        output_file = fileid
        path = xchadecrypt_file(output_file, deoutput_file, cipher)
        decode_image(output_file, deoutput_file)
    except:
        pass

    return render_template("viewimage.html", path=path)


if __name__ == '__main__':
    app.run(debug=True)
