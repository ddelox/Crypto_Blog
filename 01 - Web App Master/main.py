import os, hashlib
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from forms import AddForm
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
Bootstrap5(app)
ckeditor = CKEditor(app)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

YEAR = datetime.now().year

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).filter_by(id=user_id).first()

# CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = 'blog_post'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    author_id: Mapped[str] = mapped_column(Integer, nullable=True)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    salt: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html",
                           all_posts=posts,
                           year=YEAR,
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())

@app.route('/show_post/<int:post_id>')
def show_post(post_id):
    requested_post = db.session.query(BlogPost).get_or_404(post_id)
    return render_template("post.html",
                           post=requested_post,
                           year=YEAR,
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())


@app.route('/add_new_post', methods=["GET","POST"])
@login_required
def add_new_post():
    post_id = request.args.get('post_id', default=None, type=int)
    add_form = AddForm()
    print(f"id: {post_id}\n"
          f"Clicked Submit: {add_form.validate_on_submit()}")
    if add_form.validate_on_submit():
        save_and_exit(add_form)
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html",
                           add_form=add_form,
                           post_id=post_id,
                           year=YEAR,
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())

def save_and_exit(add_form):
    new_post = BlogPost(
        title=add_form.title.data,
        subtitle=add_form.subtitle.data,
        date=get_current_date(),
        author= current_user.name,
        author_id= current_user.id,
        img_url=add_form.img_url.data,
        body=add_form.body.data
    )
    db.session.add(new_post)
    print(f"\n-------------Added new post to db\ntitle: {new_post.title}\nid: {new_post.id}\n-------------")
    db.session.commit()

def get_current_date():
    my_date = datetime.now()
    return f"{my_date.strftime("%B")} {datetime.now().day}, {datetime.now().year}"

@app.route("/edit-post/<int:post_id>", methods=["GET","POST"])
@login_required
def edit_post(post_id):
    print(post_id)
    post_found = db.session.query(BlogPost).get_or_404(post_id)
    add_form = AddForm(
        title=post_found.title,
        subtitle=post_found.subtitle,
        author=post_found.author,
        author_id=post_found.author_id,
        img_url=post_found.img_url,
        body=post_found.body
    )
    print(f"check: {add_form.title.data}, {add_form.subtitle.data}")
    if add_form.validate_on_submit():
        post_found.title = add_form.title.data
        post_found.subtitle = add_form.subtitle.data
        post_found.img_url = add_form.img_url.data
        post_found.body = add_form.body.data
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html",
                           add_form=add_form,
                           post_id=post_id,
                           year=YEAR,
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())

@app.route("/delete_post/<int:post_id>", methods=["GET", "POST"])
@login_required
def delete_post(post_id):
    post_dying = db.session.query(BlogPost).get_or_404(post_id)
    print(f"DELETING... [id: {post_dying.id}, title: {post_dying.title}, subtitle: {post_dying.subtitle}]")
    db.session.delete(post_dying)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


# Below is the code from previous lessons. No changes needed.
@app.route("/about")
def about():
    return render_template("about.html",
                           year=YEAR,
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())


@app.route("/contact")
def contact():
    return render_template("contact.html",
                           year=YEAR,
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())

def admin_check():
    if current_user.is_authenticated:
        if current_user.id == 1:
            return True
        return False
    else:
        return False

# ADMIN CHECK - WRAPPER FUNCTION -----------------------------
# def admin_only(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         #If id is not 1 then return abort with 403 error
#         if current_user.id != 1:
#             return abort(403)
#         #Otherwise continue with the route function
#         return f(*args, **kwargs)
#     return decorated_function
# -----------------------------------------------------------

@app.route('/login', methods=["GET","POST"])
def login():
    print(f"IS_LOGGED_IN: {current_user.is_authenticated}")
    if request.form:
        email = request.form.get("email").lower()
        password_to_check = request.form.get("password")
        user_found = db.session.query(User).filter_by(email=email).first()
        if user_found:
            if verify_password(user_found.password, user_found.salt, password_to_check):
                login_user(user_found)
                print_log_login(email=current_user.email, logged_in=current_user.is_authenticated)
                return redirect(url_for("get_all_posts", name=user_found.name))
            else:
                return render_template("login.html", message="Wrong password.", logged_in=current_user.is_authenticated)
        else:
            return render_template("login.html", message="E-mail not found, register first.", logged_in=current_user.is_authenticated)
    return render_template("login.html", message="", logged_in=current_user.is_authenticated)

def verify_password(stored_password, salt, password_to_check):
    salt_bytes = bytes.fromhex(salt)
    password_hash = hashlib.scrypt(
        password_to_check.encode('utf-8'),
        salt=salt_bytes,
        n=16384,
        r=8,
        p=1,
        dklen=64
    )
    # Compare the hashes
    return password_hash.hex() == stored_password

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.form:
        name = request.form.get("name")
        email = request.form.get("email")
        password, salt = hash_password(request.form.get("password"))

        user_found = db.session.query(User).filter_by(email=email).first()
        if not user_found:
            new_user = User(
                email=email.lower(),
                password=password,
                salt=salt,
                name=name.capitalize()
            )
            db.session.add(new_user)
            db.session.commit()
            print_log_login(email=new_user.email)
            logout_user()
            return redirect(url_for("login"))
        else:
            return render_template("register.html",
                                   message="User already exists.",
                                   logged_in=current_user.is_authenticated,
                                   is_admin=admin_check())
    return render_template("register.html",
                           message="",
                           logged_in=current_user.is_authenticated,
                           is_admin=admin_check())


@app.route('/logout')
@login_required
def logout():
    print_log_login(email=current_user.email)
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for("login"))

def print_log_login(email, logged_in=False):
    if logged_in:
        print(f"[{datetime.now()}] Logged-in: {email}")
    else:
        print(f"[{datetime.now()}] Logged-out: {email}")

def hash_password(word):
    salt = os.urandom(16)
    hashed = hashlib.scrypt(
        word.encode('utf-8'),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64
    )
    return hashed.hex(), salt.hex()

if __name__ == "__main__":
    app.run(debug=True, port=5003)
