import sqlite3
import string
import random
import cv2
import blowfish

# Connect to the SQLite database
con = sqlite3.connect('data.db')
cur = con.cursor()
def working():
        con = sqlite3.connect("store.db")
        y = con.execute("select * from sharingtable where userid=?",
                        ([2])).fetchall()
        vx = []
        print(y)
        for k in y:
            k = list(k)
            print(k)
            val = con.execute("select count(*) from requesttable where fileid=? and userid=?",
                              (k[1], 2)).fetchall()
            if (val[0][0] != 0):
                n = ""

            else:
                n = "Request"
            k.append(n)
            count = con.execute(
                "select * from sharing  where fileid=?", ([k[1]])).fetchone()
            
            k.append(count[-1])

            apcount = con.execute("select count(*) from requesttable where fileid=? and userid=? and status!='not'",
                                  (k[1], 2)).fetchone()

            k.append(apcount[0])
            vx.append(k)
            

working()
