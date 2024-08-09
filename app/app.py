from flask import Flask, render_template, redirect, session, flash, url_for
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///auth_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = True 
app.config['SECRET_KEY'] = 'loki19'
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False

with app.app_context():
    connect_db(app)
    db.create_all()

toolbar = DebugToolbarExtension(app)


def get_current_user():
    """Get the current logged in user."""
    return session.get('user_id')   # return the username string


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        """Redirect to login page if user is not logged in."""
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Homepage."""
    return redirect('/register')



@app.route('/register', methods = ['GET', 'POST'])
def register():
    """Register new user."""
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        user = User.register(username, password, email, first_name, last_name)

        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.username

        return redirect('/users/' + user.username)

    return render_template('register.html', form = form)


@app.route('/users/<username>', methods = ['GET', 'POST'])
def secret(username):
    """Secret page for logged in users only."""

    form = FeedbackForm()
    current_user = User.query.filter_by(username = session.get('user_id')).first()
    feedbacks = Feedback.query.all()

    user = User.query.filter_by(username = username).first()
    if 'user_id' not in session :
        flash('You must be logged in to view this page!', 'danger')
        return redirect('/')
    
    return render_template('feedback.html', current_user = current_user, form = form , feedbacks = feedbacks)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login user."""
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.authenticate(username, password)

        if user:
            session['user_id'] = user.username  # Ensure this is set correctly
            flash(f"Welcome back, {user.username}!")
            return redirect(url_for('secret', username=user.username))
        else:
            flash('Invalid credentials.', 'danger')
            form.username.errors = ['Invalid username/password.']

    return render_template('login.html', form=form)



@app.route('/logout')
def logout():
    """Logout user and redirect to login page."""
    session.pop('user_id')
    return redirect('/login')


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
@login_required
def add_feedback(username):
    """Add feedback for user."""
    form = FeedbackForm()
    current_user = User.query.filter_by(username=session.get('user_id')).first()

    if not current_user:
        flash('You must be logged in to add feedback.', 'danger')
        return redirect('/login')

    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        feedback = Feedback(title=title, content=content, username=username)

        db.session.add(feedback)
        db.session.commit()

        return redirect(url_for('secret', username=username))

    return render_template('add_feedback.html', form=form, current_user=current_user, username = username)


@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
@login_required
def update_feedback(feedback_id):
    """Update feedback for user."""
    feedback = Feedback.query.get_or_404(feedback_id)
    current_user = session.get('user_id')  # Get the current username from session

    # Ensure that the current user is the owner of the feedback
    if feedback.username != current_user:
        flash("You don't have permission to edit this feedback.", "danger")
        return redirect(url_for('secret', username=current_user))

    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()
        flash("Feedback updated successfully.", "success")
        return redirect(url_for('secret', username=feedback.username))

    return render_template('update_feedback.html', form=form, feedback=feedback, current_user=current_user)



@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
@login_required
def delete_feedback(feedback_id):
    """Delete feedback for user."""
    feedback = Feedback.query.get_or_404(feedback_id)
    current_user = User.query.filter_by(username=session.get('user_id')).first()

    if not current_user or current_user.username != feedback.username:
        flash('You are not authorized to delete this feedback.', 'danger')
        return redirect(url_for('secret', username=current_user.username))

    db.session.delete(feedback)
    db.session.commit()
    flash('Feedback deleted successfully.', 'success')
    return redirect(url_for('secret', username=current_user.username))



















