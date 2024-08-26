import datetime
import os
from flask import Flask,request,session,jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import functools
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key="123nima123"
UPLOAD_FOLDER = '/Users/niman/Desktop/accadamy/Instagram/images'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

conn = sqlite3.connect("instagram.db")
cursor = conn.cursor()

cursor.execute('''
       CREATE TABLE IF NOT EXISTS people (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           name TEXT NOT NULL UNIQUE,
           password TEXT NOT NULL
       )
       ''')
cursor.execute('''
       CREATE TABLE IF NOT EXISTS posts (
           id INTEGER PRIMARY KEY AUTOINCREMENT,
           description TEXT NOT NULL,
           date TEXT NOT NULL,
           image_path TEXT,
           post_id INTEGER NOT NULL,
           FOREIGN KEY (post_id) REFERENCES people(id)
       )
       ''')
conn.commit()

def login_required(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        token = session.get("token")
        if not token:
            return jsonify({"message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrap


def get_db ():
    conn = sqlite3.connect("instagram.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/signup",methods=["POST"])
def signup():
    data=request.get_json()
    name=data["name"]
    password=data["password"]
    hashed_password = generate_password_hash(password)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO people (name, password ) VALUES (?,  ? )',
                   (name, hashed_password))
    conn.commit()
    conn.close()
    return {"massage":"sucssesful"}


@app.route("/login",methods=["POST"])
def login():
    data = request.get_json()
    name = data['name']
    password = data['password']
    conn = get_db()
    user = conn.execute('SELECT * FROM people WHERE name = ?', (name,)).fetchone()
    if user and check_password_hash(user['password'], password):
        session['token'] = jwt.encode({"password": password}, "secret", algorithm="HS256")
        session['user_id'] = user['id']
        session['username'] = user['name']
        return jsonify(token=session['token']), 200
    return jsonify({"message": "Invalid credentials"}), 401



@app.route("/posts",methods=["POST","GET"])
@login_required
def posts():
    if request.method=="POST":
        token = session.get("token")

        desc=request.form.get("description")
        image_file = request.files.get("image")

        if image_file:

            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
        else:
            image_path = None

        date = str(datetime.datetime.now().isoformat())
        user_id = session["user_id"]

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO posts (description, date, image_path, post_id) VALUES (?, ?, ?, ?)',
                       (desc, date, image_path, user_id))
        conn.commit()
        return {"message": "Post created"}

    conn = get_db()
    post = conn.execute('SELECT * FROM posts ', ).fetchall()
    conn.close()

    post_list = [dict(row) for row in post]
    return jsonify(post_list), 200


@app.route("/myPosts",methods=["GET"])
@login_required
def myPost():
    id=session.get("user_id")
    conn = get_db()
    post = conn.execute('SELECT * FROM posts where post_id=?',(str(id)) ).fetchall()
    conn.close()
    post_list = [dict(row) for row in post]
    return jsonify(post_list), 200


@app.route("/myPostUpdate/<int:id>", methods=["PUT"])
@login_required
def myPostPut(id):
    user_id = session.get("user_id")
    conn = get_db()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND post_id = ?', (id, user_id)).fetchone()
    if not post:
        return {"message": "Unauthorized - You can only update your own posts"}, 403

    description = request.form.get("description")
    image_file = request.files.get("image")
    cursor = conn.cursor()
    if image_file:
        filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(image_path)
        cursor.execute('UPDATE posts SET description = ?, image_path = ? WHERE id = ?', (description, image_path, id))
    else:
        cursor.execute('UPDATE posts SET description = ? WHERE id = ?', (description, id))

    conn.commit()
    return {"message": "Post updated"}


@app.route("/myPostDelete/<int:id>",methods=["DELETE"])
@login_required
def myPostDel(id):
    user_id = session.get("user_id")
    conn = get_db()
    post = conn.execute('SELECT * FROM posts WHERE id = ? AND post_id = ?', (id, user_id)).fetchone()
    if not post:
        return {"message": "Unauthorized - You can only delete your own posts"}, 403
    cursor = conn.cursor()
    cursor.execute('DELETE FROM posts WHERE id = ?', (id,))
    conn.commit()

    return {"message": "Post deleted"}




@app.route("/stories",methods=["GET"])
@login_required
def stories():
    page = request.args.get('page', default=1, type=int)
    start_id = (page - 1) * 10 + 1
    conn = get_db()
    posts = conn.execute('SELECT * FROM posts WHERE id >= ? ORDER BY id ASC LIMIT ?', (start_id, 10)).fetchall()
    post_list = [dict(row) for row in posts]
    return jsonify(post_list), 200






if __name__ == '__main__':
    app.run()
