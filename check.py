import sqlite3
con = sqlite3.connect("store.db")
e=con.execute("select * from data").fetchall()
print(e)
e=con.execute("select * from sharing").fetchall()
print(e)
e=con.execute("select * from sharingtable").fetchall()


e=con.execute("select * from requesttable").fetchall()


e=con.execute("delete from sharing").fetchall()


e=con.execute("delete from sharingtable").fetchall()


e=con.execute("delete from requesttable").fetchall()
con.commit()
