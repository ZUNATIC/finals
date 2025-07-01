import os

from flask import Flask
from flask import url_for, render_template, json, redirect, request, abort

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired

from data import db_session
from data.users import User
from data.news import News
import datetime

from flask_login import LoginManager, logout_user, login_user, login_required, current_user

# --- Security Feature 1: Logging and Monitoring ---
import logging
from logging.handlers import RotatingFileHandler

# --- Security Feature 2 & 3: Secure Headers and CSP ---
from flask_talisman import Talisman

# --- Security Feature 4: Rate Limiting ---
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'verystrong_secret_key'

# --- Logging Configuration ---
# Logs security events to 'security.log' with rotation
handler = RotatingFileHandler('security.log', maxBytes=100000, backupCount=3)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# --- Flask-Talisman for Secure Headers and CSP ---
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'"],  # Disallow inline scripts and external scripts
}
Talisman(app, content_security_policy=csp, force_https=False)  # Set force_https=True in production

# --- Flask-Limiter for Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


class RegisterForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль', validators=[DataRequired()])
    name = StringField('Имя пользователя', validators=[DataRequired()])
    about = TextAreaField("Немного о себе")
    submit = SubmitField('Войти')


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField("Запомнить меня")
    submit = SubmitField('Войти')


class NewsForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired()])
    content = TextAreaField("Содержание")
    is_private = BooleanField("Личное")
    submit = SubmitField('Сохранить')


@app.route("/")
def index():
    session = db_session.create_session()
    if current_user.is_authenticated:
        news = session.query(News).filter(
            (News.user == current_user) | (News.is_private != True))
    else:
        news = session.query(News).filter(News.is_private != True)
    return render_template("index.html", news=news)


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User(
            name=form.name.data,
            email=form.email.data,
            about=form.about.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)


# --- Rate Limiting applied to login route ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", error_message="Too many login attempts. Please try again later.")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            app.logger.info(f"Successful login for user: {form.email.data}")
            return redirect("/")
        # --- Logging failed login attempt ---
        app.logger.warning(f"Failed login attempt for email: {form.email.data} from IP: {request.remote_addr}")
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/news',  methods=['GET', 'POST'])
@login_required
def add_news():
    form = NewsForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        news = News()
        news.title = form.title.data
        news.content = form.content.data
        news.is_private = form.is_private.data
        current_user.news.append(news)
        session.merge(current_user)
        session.commit()
        return redirect('/')
    return render_template('news.html', title='Добавление новости', form=form)


@app.route('/news/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_news(id):
    form = NewsForm()
    if request.method == "GET":
        session = db_session.create_session()
        news = session.query(News).filter(News.id == id,
                                          News.user == current_user).first()
        if news:
            form.title.data = news.title
            form.content.data = news.content
            form.is_private.data = news.is_private
        else:
            # --- Logging unauthorized access attempt ---
            app.logger.warning(f"Unauthorized news edit attempt by user {current_user.id} for news id {id}")
            abort(404)
    if form.validate_on_submit():
        session = db_session.create_session()
        news = session.query(News).filter(News.id == id,
                                          News.user == current_user).first()
        if news:
            news.title = form.title.data
            news.content = form.content.data
            news.is_private = form.is_private.data
            session.commit()
            return redirect('/')
        else:
            # --- Logging unauthorized access attempt ---
            app.logger.warning(f"Unauthorized news edit attempt by user {current_user.id} for news id {id}")
            abort(404)
    return render_template('news.html', title='Редактирование новости', form=form)


@app.route('/news_delete/<int:id>', methods=['GET', 'POST'])
@login_required
def news_delete(id):
    session = db_session.create_session()
    news = session.query(News).filter(News.id == id,
                                      News.user == current_user).first()
    if news:
        session.delete(news)
        session.commit()
    else:
        # --- Logging unauthorized delete attempt ---
        app.logger.warning(f"Unauthorized news delete attempt by user {current_user.id} for news id {id}")
        abort(404)
    return redirect('/')


def main():
    db_session.global_init("db/blogs.sqlite")
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
    # app.run(port=5000, host='127.0.0.1')



if __name__ == '__main__':
    main()
