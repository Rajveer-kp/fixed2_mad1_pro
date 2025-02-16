from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from app.models.user import User
from app import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/')
def index():
    """Redirects to login page by default."""
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user:
            if user.is_blocked:  # ✅ Prevent blocked users from logging in
                flash("Your account has been blocked by the admin.", "danger")
                return redirect(url_for('auth.login'))
            
            if user.check_password(password):
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role

                flash(f'Welcome, {user.username}!', 'success')

                if user.role == 'admin':
                    return redirect(url_for('admin.dashboard'))
                return redirect(url_for('user.dashboard'))
        
        flash('Invalid email or password', 'danger')

    return render_template('login.html')




@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'danger')
            return redirect(url_for('auth.register'))
            
        # Create a new user
        user = User(username=username, email=email, role="user")  # Default role is 'user'
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@auth_bp.route('/logout')
def logout():
    """Logs out the user and clears session."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/debug-session')
def debug_session():
    """Debugging route to check session values."""
    return {
        "user_id": session.get('user_id'),
        "username": session.get('username'),  # Should NOT be None
        "role": session.get('role')
    }
