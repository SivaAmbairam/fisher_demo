import tempfile
import gevent
# import eventlet
# eventlet.monkey_patch()
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import psutil
from apscheduler.schedulers.background import BackgroundScheduler


import signal
import time
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, flash
import threading
import subprocess
import os
import jaydebeapi
import jpype
import ssl
import logging
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from scheduler import schedule_task, stop_scheduled_task, get_scheduled_tasks, schedule_monthly_task, scheduled_tasks
from datetime import datetime
import uuid
import json
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPExceptionError
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import session
import platform


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scheduled_tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app, async_mode='threading')

db = SQLAlchemy(app)

scheduler = BackgroundScheduler()
scheduler.start()

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)


# LDAP Configuration
# LDAP_HOST = '192.168.20.242'
# LDAP_BASE_DN = 'OU=Contractors,OU=IT,OU=Departments,DC=FSI'
# LDAP_USER_DN = 'OU=Contractors,OU=IT,OU=Departments,DC=FSI'
# LDAP_GROUP_DN = 'OU=Contractors,OU=IT,OU=Departments,DC=FSI'
# LDAP_USER_RDN_ATTR = 'cn'
# LDAP_USER_LOGIN_ATTR = 'sAMAccountName'
# LDAP_BIND_USER_DN = r'CN=svc_webscrape,CN="Managed Service Accounts",DC=FSI'
# LDAP_BIND_USER_PASSWORD = 'A9wCQKVPNLzm!d$AC$fY'

# LDAP Configuration
# LDAP Configuration
LDAP_HOST = '192.168.20.242'  # Keeping this as is, as it's not provided in the image
LDAP_BASE_DN = 'DC=FSI'
LDAP_USER_DN = 'OU=Contractors,OU=IT,OU=Departments,DC=FSI;CN=Managed Service Accounts,DC=FSI'
LDAP_GROUP_DN = 'OU=Groups,DC=FSI'
LDAP_USER_RDN_ATTR = 'cn'
LDAP_USER_LOGIN_ATTR = 'sAMAccountName'
LDAP_BIND_USER_DN = 'CN=svc_webscrape,CN=Managed Service Accounts,DC=FSI'  # Keeping this from the previous configuration

# Note: The password is not included in the image, so I'm keeping it as is in the script
LDAP_BIND_USER_PASSWORD = 'A9wCQKVPNLzm!d$AC$fY'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Global state object
global_state = {
    'run_button_disabled': False,
    'stop_button_disabled': True,
    'schedule_button_disabled': False,
    'stop_schedule_button_disabled': True,
    'scripts_running': False,
    'scheduled_tasks': []
}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    has_access = db.Column(db.Boolean, default=False)
    is_runner = db.Column(db.Boolean, default=False)  # New column
    receive_notifications = db.Column(db.Boolean, default=False)

    @property
    def is_runner_or_admin(self):
        return self.is_admin or self.is_runner

class ScheduledTask(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    script_name = db.Column(db.String(100), nullable=False)
    run_date = db.Column(db.Date, nullable=False)
    run_time = db.Column(db.Time, nullable=False)
    recurrence_type = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='Scheduled')


    def to_dict(self):
        return {
            'id': self.id,
            'script_name': self.script_name,
            'run_date': self.run_date.strftime('%Y-%m-%d'),
            'run_time': self.run_time.strftime('%H:%M'),
            'recurrence_type': self.recurrence_type,
            'status': self.status
        }

state_lock = threading.Lock()

SCRIPTS_DIRECTORY = r"D:\svc_webscrape\Deployment 2\Scrapping Scripts"
COMPARISON_SCRIPT = r"D:\svc_webscrape\Deployment 2\Scrapping Scripts\Run_Script"
FISHER_COMPARISON_SCRIPT = r'D:\svc_webscrape\Deployment 2\Scrapping Scripts\Fisher_Script'
stop_execution = False
script_status = {}
script_output = {}

logging.basicConfig(level=logging.DEBUG)

def load_config():
    config_path = 'config.json'
    if os.path.exists(config_path):
        with open(config_path, 'r') as config_file:
            config = json.load(config_file)
            app.logger.info(f"Loaded config: {config}")
            return config
    app.logger.warning("Config file not found, using default password")
    return {"admin_password": "123123"}  # Default password if config file doesn't exist

@app.route('/update_notification_status', methods=['POST'])
@login_required
def update_notification_status():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'You do not have permission to perform this action.'}), 403

    data = request.json
    username = data.get('username')
    receive_notifications = data.get('receiveNotifications', False)

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    user.receive_notifications = receive_notifications
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Notification status for {username} updated successfully.',
        'receive_notifications': user.receive_notifications
    })

def save_config(config):
    with open('config.json', 'w') as config_file:
        json.dump(config, config_file, indent=2)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_ldap_connection():
    server = Server(LDAP_HOST, get_info=ALL)
    return Connection(server, LDAP_BIND_USER_DN, LDAP_BIND_USER_PASSWORD, auto_bind=True)

def get_ldap_users():
    with get_ldap_connection() as conn:
        conn.search(LDAP_BASE_DN, '(objectClass=person)', SUBTREE, attributes=['cn', 'userPrincipalName'])
        return [{'username': entry['cn'].value, 'userPrincipalName': entry['userPrincipalName'].value} for entry in conn.entries]

# Added
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        app.logger.info(f"Login attempt for user: {username}")

        if not username or not password:
            app.logger.warning("Missing username or password")
            flash('Please provide both username and password')
            return render_template('login.html')

        # Check if it's the local admin
        config = load_config()
        if username == 'admin':
            if password == config['admin_password']:
                user = User.query.filter_by(username='admin').first()
                if not user:
                    user = User(username='admin', is_admin=True, has_access=True)
                    db.session.add(user)
                    db.session.commit()
                login_user(user)
                app.logger.info("Admin logged in successfully")
                return redirect(url_for('index'))
            else:
                app.logger.warning("Invalid admin password")
                flash('Invalid admin password')
                return render_template('login.html')

        # LDAP authentication for non-admin users
        try:
            app.logger.info(f"Attempting LDAP authentication for user: {username}")
            server = Server(LDAP_HOST, get_info=ALL, connect_timeout=20)

            # First, try authenticating as the service account
            service_account_dn = f"CN={username},CN=Managed Service Accounts,DC=FSI"
            try:
                with Connection(server, service_account_dn, password, auto_bind=True, read_only=True,
                                receive_timeout=10) as conn:
                    app.logger.info("Service account authentication successful")
                    user = User.query.filter_by(username=username).first()
                    if user and user.has_access:
                        login_user(user)
                        session['is_runner'] = user.is_runner_or_admin
                        app.logger.info(f"Service account {username} logged in successfully")
                        return redirect(url_for('index'))
                    elif not user:
                        user = User(username=username, has_access=True)
                        db.session.add(user)
                        db.session.commit()
                        login_user(user)
                        app.logger.info(f"New service account {username} created and logged in successfully")
                        return redirect(url_for('index'))
                    else:
                        app.logger.warning(f"Service account {username} does not have access")
                        flash('You do not have access to this application. Please contact an administrator.')
            except LDAPExceptionError:
                app.logger.info("Service account authentication failed, trying regular user authentication")

            # If service account authentication fails, try regular user authentication
            user_dn = f"{LDAP_USER_LOGIN_ATTR}={username},{LDAP_USER_DN}"
            with Connection(server, user_dn, password, auto_bind=True, read_only=True, receive_timeout=10) as conn:
                app.logger.info("LDAP authentication successful")
                user = User.query.filter_by(username=username).first()
                if user and user.has_access:
                    login_user(user)
                    app.logger.info(f"User {username} logged in successfully")
                    return redirect(url_for('index'))
                elif not user:
                    user = User(username=username, has_access=False)
                    db.session.add(user)
                    db.session.commit()
                    app.logger.warning(f"New user {username} created but does not have access")
                    flash(
                        'Your account has been created, but you do not have access yet. Please contact an administrator.')
                else:
                    app.logger.warning(f"User {username} does not have access")
                    flash('You do not have access to this application. Please contact an administrator.')


            user = User.query.filter_by(username=username).first()
            if user and user.has_access:
                login_user(user)
                app.logger.info(f"User {username} logged in successfully")
                return redirect(url_for('index'))
            elif not user:
                user = User(username=username, has_access=False, is_admin=False)
                db.session.add(user)
                db.session.commit()
                app.logger.warning(f"New user {username} created but does not have access")
                flash('Your account has been created, but you do not have access yet. Please contact an administrator.')
            else:
                app.logger.warning(f"User {username} does not have access")
                flash('You do not have access to this application. Please contact an administrator.')


        except LDAPExceptionError as e:
            app.logger.error(f"LDAP Error: {str(e)}")
            if "invalid credentials" in str(e).lower():
                flash('Invalid username or password')
            elif "connection timeout" in str(e).lower():
                flash(
                    'Authentication service is currently unavailable. Please try again later or contact an administrator.')
            else:
                flash('LDAP authentication failed. Please try again or contact an administrator.')

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been successfully logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/update_admin_status', methods=['POST'])
@login_required
def update_admin_status():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'You do not have permission to perform this action.'}), 403

    data = request.json
    username = data.get('username')
    is_admin = data.get('isAdmin')

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    user.is_admin = is_admin
    db.session.commit()

    return jsonify({'status': 'success', 'message': f'Admin status for {username} updated successfully.'})

def stop_execution_handler(signum, frame):
    global stop_execution
    stop_execution = True

signal.signal(signal.SIGINT, stop_execution_handler)

def run_script(script_name):
    global stop_execution, script_status, script_output
    script_path = os.path.join(SCRIPTS_DIRECTORY, script_name)
    script_status[script_name] = 'Running'
    url_count = 0

    def check_and_run_comparison():
        all_completed = all(
            status.startswith('Completed') for script, status in script_status.items() if script != 'push_script.py')
        if all_completed:
            logging.debug("All scripts completed. Starting push_script.py.")
            run_script('Run_Comparison.py')

    # def fisher_push(completed_script):
    #     if completed_script == 'Fisher Products.py':
    #         logging.debug(f"{completed_script} completed. Starting Fisher_Push_Script.py.")
    #         run_script('Fisher_Push_Script.py')

    try:
        logging.debug(f"Starting script: {script_name}")
        process = subprocess.Popen(['python', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        while True:
            if stop_execution or script_status.get(script_name) == 'Stopping':
                logging.debug(f"Stopping script: {script_name}")
                try:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        child.terminate()
                    parent.terminate()
                    parent.wait(timeout=5)
                except psutil.NoSuchProcess:
                    pass
                except psutil.TimeoutExpired:
                    parent.kill()
                script_status[script_name] = f'Stopped (URLs scraped: {url_count})'
                socketio.emit('script_update', {'script_name': script_name, 'status': script_status[script_name]})
                break
            try:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    logging.debug(f'Script {script_name} output: {output.strip()}')
                    script_output[script_name] = script_output.get(script_name, '') + output
                    if output.strip().startswith('https://'):  # Count URLs
                        url_count += 1
                        script_status[script_name] = f'Running (URLs scraped: {url_count})'
                        socketio.emit('script_update',
                                      {'script_name': script_name, 'status': script_status[script_name]})
            except subprocess.TimeoutExpired:
                continue
        stdout, stderr = process.communicate()
        script_output[script_name] = script_output.get(script_name, '') + stdout + stderr
        rc = process.poll()
        if script_status.get(script_name) != f'Stopped (URLs scraped: {url_count})':
            script_status[script_name] = f'Completed (URLs scraped: {url_count})' if rc == 0 else f'Error: {stderr.strip()}'
            # check_and_run_comparison()
            # fisher_push(script_name)
        socketio.emit('script_update', {'script_name': script_name, 'status': script_status[script_name]})
    except Exception as e:
        logging.error(f"Exception running script {script_name}: {e}")
        script_status[script_name] = f'Error: {str(e)}'
        socketio.emit('script_update', {'script_name': script_name, 'status': script_status[script_name]})
    finally:
        if script_name in script_status and 'Running' in script_status[script_name]:
            script_status[script_name] = f'Completed (URLs scraped: {url_count})'
            # check_and_run_comparison()
            # fisher_push(script_name)
        stop_execution = False  # Reset stop_execution flag after script completes


def run_comparison():
    global stop_execution, script_status, script_output
    script_name = request.form.get('scripts')
    script_path = os.path.join(COMPARISON_SCRIPT, script_name)
    script_status[script_name] = 'Running'
    url_count = 0

    try:
        logging.debug(f"Starting script: {script_name}")
        process = subprocess.run(['python', script_path], capture_output=True, text=True, timeout=3600)

        script_output[script_name] = process.stdout + process.stderr

        if process.returncode == 0:
            script_status[script_name] = f'Completed'
        else:
            script_status[script_name] = f'Error: {process.stderr.strip()}'

    except subprocess.TimeoutExpired:
        script_status[script_name] = 'Timeout'
    except Exception as e:
        logging.error(f"Exception running script {script_name}: {e}")
        script_status[script_name] = f'Error: {str(e)}'

    return jsonify(script_status=script_status[script_name])

def run_comparison_v1():
    global stop_execution, script_status, script_output
    script_name = request.form.get('scripts')
    script_path = os.path.join(FISHER_COMPARISON_SCRIPT, script_name)
    script_status[script_name] = 'Running'
    url_count = 0

    try:
        logging.debug(f"Starting script: {script_name}")
        process = subprocess.run(['python', script_path], capture_output=True, text=True, timeout=3600)

        script_output[script_name] = process.stdout + process.stderr

        if process.returncode == 0:
            script_status[script_name] = f'Completed'
        else:
            script_status[script_name] = f'Error: {process.stderr.strip()}'

    except subprocess.TimeoutExpired:
        script_status[script_name] = 'Timeout'
    except Exception as e:
        logging.error(f"Exception running script {script_name}: {e}")
        script_status[script_name] = f'Error: {str(e)}'

    return jsonify(script_status=script_status[script_name])


def terminate_all_scripts():
    global stop_execution, script_status
    stop_execution = True
    current_process = psutil.Process()
    children = current_process.children(recursive=True)
    for child in children:
        try:
            os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        except:
            child.terminate()

    gone, alive = psutil.wait_procs(children, timeout=3)
    for p in alive:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except:
            p.kill()

    for script_name in script_status:
        if script_status[script_name] == 'Running':
            script_status[script_name] = 'Stopped'
            socketio.emit('script_update', {'script_name': script_name, 'status': 'Stopped'})


UNWANTED_SCRIPTS = ['module_package.py', 'push_script.py', 'Fisher_Push_Script.py']

# Added
@app.route('/')
@login_required
def index():
    try:
        username = current_user.username
        is_runner = current_user.is_runner_or_admin
        app.logger.info(f"SCRIPTS_DIRECTORY: {SCRIPTS_DIRECTORY}")
        app.logger.info(f"Directory contents: {os.listdir(SCRIPTS_DIRECTORY)}")

        scripts = [f for f in os.listdir(SCRIPTS_DIRECTORY) if f.endswith('.py') and f not in UNWANTED_SCRIPTS]
        app.logger.info(f"Filtered scripts: {scripts}")

        # Query all local users
        local_users = User.query.all()

        # Convert local_users to a list of dictionaries
        local_users_data = [
            {
                'id': user.id,
                'username': user.username,
                'is_admin': user.is_admin,
                'has_access': user.has_access,
                'is_runner': user.is_runner_or_admin
            } for user in local_users
        ]

        return render_template('index.html', scripts=scripts, username=username, is_runner=is_runner, local_users=local_users_data)
    except Exception as e:
        app.logger.error(f"Error in index route: {str(e)}", exc_info=True)
        return jsonify({'status': f'Error loading scripts: {str(e)}'}), 500

@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(f"404 error: {request.url}")
    return "404 Not Found", 404

@socketio.on('connect')
def handle_connect():
    emit('state_update', global_state)

@socketio.on('run_scripts')
def handle_run_scripts(data):
    scripts = data['scripts']
    if not scripts:
        emit('error', {'message': 'No scripts selected.'})
        return

    with state_lock:
        global_state['run_button_disabled'] = True
        global_state['stop_button_disabled'] = False
        global_state['schedule_button_disabled'] = True
        global_state['stop_schedule_button_disabled'] = True
        global_state['scripts_running'] = True

    global stop_execution
    stop_execution = False

    for script in scripts:
        threading.Thread(target=run_script, args=(script,)).start()
        update_task_status(script, 'Running')

    emit('state_update', global_state, broadcast=True)
    emit('script_started', {'username': current_user.username}, broadcast=True)


@socketio.on('run_comparison_v1')
def handle_run_comparison_v1(data):
    scripts = data.get('scripts', [])
    related_scripts = data.get('related_scripts', [])

    if not scripts:
        emit('error', {'message': 'No scripts selected for comparison.'})
        return

    with state_lock:
        global_state['run_button_disabled'] = True
        global_state['stop_button_disabled'] = False
        global_state['schedule_button_disabled'] = True
        global_state['stop_schedule_button_disabled'] = True
        global_state['scripts_running'] = True

    global stop_execution
    stop_execution = False

    # Start a thread for each script
    for script in scripts:
        threading.Thread(target=run_comparison, args=(script, related_scripts)).start()
        update_task_status(script, 'Running')

    emit('state_update', global_state, broadcast=True)
    emit('comparison_started', {'username': current_user.username, 'scripts': scripts}, broadcast=True)

@socketio.on('run_comparison')
def handle_run_scripts(data):
    scripts = data['scripts']
    if not scripts:
        emit('error', {'message': 'No scripts selected.'})
        return

    with state_lock:
        global_state['run_button_disabled'] = True
        global_state['stop_button_disabled'] = False
        global_state['schedule_button_disabled'] = True
        global_state['stop_schedule_button_disabled'] = True
        global_state['scripts_running'] = True

    global stop_execution
    stop_execution = False

    for script in scripts:
        threading.Thread(target=run_script, args=(script,)).start()
        update_task_status(script, 'Running')

    emit('state_update', global_state, broadcast=True)
    emit('script_started', {'username': current_user.username}, broadcast=True)
@socketio.on('stop_scripts')
def handle_stop_scripts():
    terminate_all_scripts()

    with state_lock:
        global_state['run_button_disabled'] = False
        global_state['stop_button_disabled'] = True
        global_state['schedule_button_disabled'] = False
        global_state['scripts_running'] = False

    emit('state_update', global_state, broadcast=True)
    emit('all_stopped', {'status': 'All scripts have been stopped.'}, broadcast=True)
    emit('Scripts Stopped', {'username': current_user.username}, broadcast=True)

@socketio.on('schedule_scripts')
def handle_schedule_scripts(data):
    global stop_execution
    stop_execution = False
    scripts = data['scripts']
    start_date = data['start_date']
    start_time = data['start_time']
    recurrence_type = data['recurrence_type']

    unique_scripts = list(set(scripts))
    scheduled_scripts = []

    for script in unique_scripts:
        if recurrence_type == 'monthly':
            schedule_monthly_task(script, start_date, start_time, run_script)
        else:
            schedule_task(script, start_date, start_time, run_script)
        scheduled_scripts.append(script)

    update_and_emit_global_state({
        'run_button_disabled': True,
        'stop_button_disabled': True,
        'schedule_button_disabled': True,
        'stop_schedule_button_disabled': False
    })

    if recurrence_type == 'monthly':
        status = f'Scheduled {scheduled_scripts} monthly from {start_date} at {start_time}'
    else:
        status = f'Scheduled {scheduled_scripts} for {start_date} at {start_time}'

    tasks = get_scheduled_tasks()
    emit('schedule_update', {'status': status, 'tasks': tasks}, broadcast=True)
    emit('state_update', global_state, broadcast=True)
    emit('script_scheduled', {'username': current_user.username}, broadcast=True)


@socketio.on('stop_all')
def handle_stop_all():
    global stop_execution, script_status, scheduled_tasks
    stop_execution = True

    # Stop all scheduled tasks
    scheduler.remove_all_jobs()

    # Terminate all running scripts
    terminate_all_scripts()

    # Clear scheduled tasks
    scheduled_tasks.clear()

    with state_lock:
        global_state['run_button_disabled'] = False
        global_state['stop_button_disabled'] = True
        global_state['schedule_button_disabled'] = False
        global_state['stop_schedule_button_disabled'] = True
        global_state['scripts_running'] = False
        global_state['scheduled_tasks'] = []

    emit('state_update', global_state, broadcast=True)
    emit('all_stopped', {'status': 'All scheduled tasks and running scripts have been stopped.'}, broadcast=True)

    # Update status after stopping
    for script_name in script_status:
        script_status[script_name] = 'Stopped'
        socketio.emit('script_update', {'script_name': script_name, 'status': 'Stopped'})

    # Clear the database
    with app.app_context():
        ScheduledTask.query.delete()
        db.session.commit()

    emit('tasks_updated', {'tasks': []}, broadcast=True)


def update_task_status(script_name, status):
    for task in scheduled_tasks:
        if task['script_name'] == script_name:
            task['status'] = status
            break


@app.route('/update_state', methods=['POST'])
def update_state():
    global global_state
    try:
        new_state = request.json
        if new_state is None:
            raise ValueError("No JSON data received")
        app.logger.info(f"Received state update: {new_state}")
        with state_lock:
            global_state.update(new_state)
        app.logger.info(f"Updated global state: {global_state}")
        return jsonify(global_state)
    except Exception as e:
        app.logger.error(f"Error updating state: {str(e)}")
        return jsonify({'error': str(e)}), 400


@app.route('/status', methods=['GET'])
def status():
    try:
        return jsonify(script_status)
    except Exception as e:
        logging.error(f"Error getting status: {str(e)}")
        return jsonify({'status': f'Error getting status: {str(e)}'}), 500


@app.route('/schedule_scripts', methods=['POST'])
def schedule_scripts():
    try:
        scripts = request.form.getlist('scripts')
        start_date = request.form.get('start-date')
        start_time = request.form.get('start-time')
        recurrence_type = request.form.get('recurrence-type')

        run_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        run_time = datetime.strptime(start_time, '%H:%M').time()

        scheduled_scripts = []
        for script in scripts:
            new_task = ScheduledTask(
                id=str(uuid.uuid4()),
                script_name=script,
                run_date=run_date,
                run_time=run_time,
                recurrence_type=recurrence_type,
                status='Scheduled'
            )
            db.session.add(new_task)
            scheduled_scripts.append(script)

            # Schedule the task
            if recurrence_type == 'monthly':
                task = schedule_monthly_task(script, start_date, start_time, run_script)
            else:
                task = schedule_task(script, start_date, start_time, run_script)

            if task is None:
                return jsonify({'status': f'Error scheduling script: {script}'}), 500

        db.session.commit()

        status = f'Scheduled {scheduled_scripts} for {start_date} at {start_time}'
        if recurrence_type == 'monthly':
            status = f'Scheduled {scheduled_scripts} monthly from {start_date} at {start_time}'

        tasks = ScheduledTask.query.all()
        # socketio.emit('tasks_updated', {'tasks': [task.to_dict() for task in tasks]})
        return jsonify({
            'status': status,
            'tasks': [task.to_dict() for task in tasks]
        })
    except Exception as e:
        logging.error(f"Error scheduling script: {str(e)}")
        return jsonify({'status': f'Error scheduling script: {str(e)}'}), 500


@app.route('/stop_scheduled_scripts', methods=['POST'])
def stop_scheduled_scripts():
    try:
        script_name = request.form.get('script_name')

        # Stop all scheduled tasks
        scheduler.remove_all_jobs()

        # Terminate any running scripts
        terminate_all_scripts()

        # Clear the database
        if script_name:
            ScheduledTask.query.filter_by(script_name=script_name).delete()
        else:
            ScheduledTask.query.delete()

        with state_lock:
            global_state['run_button_disabled'] = False
            global_state['stop_button_disabled'] = True
            global_state['schedule_button_disabled'] = False
            global_state['stop_schedule_button_disabled'] = True
            global_state['scripts_running'] = False

        db.session.commit()
        sync_tasks_with_db()

        # Clear the scheduled_tasks list
        global scheduled_tasks
        scheduled_tasks = []

        updated_tasks = ScheduledTask.query.all()
        socketio.emit('tasks_updated', {'tasks': [task.to_dict() for task in updated_tasks]}, namespace='/')
        socketio.emit('state_update', global_state, broadcast=True)
        emit('schedule_stopped', {'username': current_user.username}, broadcast=True)

        return jsonify({'status': 'All scheduled tasks and running scripts have been stopped.'})
    except Exception as e:
        logging.error(f"Error stopping scheduled tasks: {str(e)}")
        db.session.rollback()
        return jsonify({'status': f'Error stopping scheduled tasks: {str(e)}'}), 500


def stop_specific_scheduled_task(script_name):
    global scheduled_tasks
    tasks_to_remove = [task for task in scheduled_tasks if task['script_name'] == script_name]

    for task in tasks_to_remove:
        scheduler.remove_job(task['job_id'])

    scheduled_tasks = [task for task in scheduled_tasks if task not in tasks_to_remove]

    if socketio:
        socketio.emit('schedule_update', {'tasks': get_scheduled_tasks()})

def sync_tasks_with_db():
    global scheduled_tasks
    db_tasks = ScheduledTask.query.all()
    scheduled_tasks = [{
        'script_name': task.script_name,
        'run_date': task.run_date.strftime('%Y-%m-%d'),
        'run_time': task.run_time.strftime('%H:%M'),
        'thread': None,  # You might need to recreate the thread here
        'status': task.status
    } for task in db_tasks]




def stop_all_running_scripts():
    global stop_execution, script_status
    stop_execution = True
    for script_name in script_status:
        if script_status[script_name] == 'Running':
            script_status[script_name] = 'Stopping'

def reinitialize_scheduler():
    global scheduled_tasks
    with state_lock:
        scheduled_tasks = []
        for task in ScheduledTask.query.all():
            schedule_task(task.script_name, task.run_date.strftime('%Y-%m-%d'), task.run_time.strftime('%H:%M'), run_script)

@app.route('/reset_state', methods=['POST'])
def reset_state():
    global stop_execution, script_status, script_output
    stop_execution = False
    script_status = {}
    script_output = {}
    return jsonify({'status': 'State reset successfully'})


def update_and_emit_global_state(new_state=None):
    global global_state
    with state_lock:
        if new_state:
            app.logger.info(f"Updating global state with: {new_state}")
            global_state.update(new_state)
        app.logger.info(f"Emitting global state: {global_state}")
        socketio.emit('state_update', global_state, broadcast=True)


@socketio.on('request_state_update')
def handle_state_update_request():
    update_and_emit_global_state()


@app.route('/get_state', methods=['GET'])
@login_required
def get_state():
    global global_state
    with state_lock:
        global_state['user_roles'] = {
            'is_admin': current_user.is_admin,
            'is_runner': current_user.is_runner,
            'has_access': current_user.has_access
        }
        return jsonify(global_state)

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


@app.route('/get_user_status', methods=['GET'])
@login_required
def get_user_status():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'Username not provided'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'username': user.username,
        'is_admin': user.is_admin,
        'has_access': user.has_access,
        'is_runner': user.is_runner_or_admin,
        'receive_notifications': user.receive_notifications
    })

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "pete.webscraper@gmail.com"
SENDER_PASSWORD = "fgny hxqb hifz nicg"

@app.route('/send_notification', methods=['POST'])
def send_notification():
    print("Mail Notification Called")
    app.logger.info("Received notification request")
    data = request.json
    subject = data.get('subject')
    message = data.get('message')
    action = data.get('action')
    app.logger.info(f"Notification details: Subject: {subject}, Message: {message}")

    username = current_user.username if current_user.is_authenticated else "Unknown User"
    action_by = "Started by" if action == 'Running' else "Stopped by"
    app.logger.info(f"Sending notification for user: {username}")
    Logged_by = f"{action_by}: {username}"
    full_message = f"{Logged_by}\n\n{message}"

    try:
        send_notifications(full_message, subject)
        app.logger.info("Notification sent successfully")
        return jsonify({"status": "success", "message": "Notification sent"})
    except Exception as e:
        app.logger.error(f"Error sending notification: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": f"Failed to send notification: {str(e)}"}), 500


def send_notifications(message, subject):
    app.logger.info("Entering send_notifications function")
    users_to_notify = User.query.filter_by(receive_notifications=True).all()
    app.logger.info(f"Users to notify: {[user.username for user in users_to_notify]}")
    additional_recipients = ['ajith@geval6.com']
    sender_email = SENDER_EMAIL
    recipients = [f"{user.username}@flinnsci.com" for user in users_to_notify]
    recipients.extend(additional_recipients)
    app.logger.info(f"All recipients: {recipients}")

    try:
        send_email(subject, message, recipients, sender_email)
        app.logger.info(f"Notifications sent to: {', '.join(recipients)}")
    except Exception as e:
        app.logger.error(f"Error in send_notifications: {str(e)}", exc_info=True)
        raise

sender_username = 'P.E.T.e - Admin'
def send_email(subject, body, recipients, sender_email):
    app.logger.info("Entering send_email function")
    message = MIMEMultipart()
    message["From"] = f"{sender_username} <{sender_email}>"
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        app.logger.info(f"Attempting to connect to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            app.logger.info("Connected to SMTP server")
            server.starttls()
            app.logger.info("TLS started")
            app.logger.info(f"Attempting to login with email: {SENDER_EMAIL}")
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            app.logger.info("Logged in successfully")

            # Explicitly set the sender and recipients
            server.sendmail(sender_email, recipients, message.as_string())
            app.logger.info(f"Email sent: {subject} to {', '.join(recipients)}")
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}", exc_info=True)
        raise


@app.route('/get_scheduling_status', methods=['GET'])
def get_scheduling_status():
    tasks = get_scheduled_tasks()
    any_scheduled = len(tasks) > 0
    any_running = any(task.get('status') == 'Running' for task in tasks)
    return jsonify({
        'status': 'Scheduled' if any_scheduled else 'Not Scheduled',
        'tasks': [{'script_name': task['script_name'], 'run_date': task['run_date'], 'run_time': task['run_time'],
                   'status': task.get('status', 'Scheduled')} for task in tasks],
        'any_scheduled': any_scheduled,
        'any_running': any_running
    })


@app.route('/check_running_scripts', methods=['GET'])
def check_running_scripts():
    any_running = any(status == 'Running' for status in script_status.values())
    return jsonify({'any_running': any_running})


@app.route('/get_scheduled_tasks', methods=['GET'])
def get_scheduled_tasks_route():
    try:
        tasks = ScheduledTask.query.all()
        return jsonify([task.to_dict() for task in tasks])
    except Exception as e:
        logging.error(f"Error getting scheduled tasks: {str(e)}")
        return jsonify({'status': f'Error getting scheduled tasks: {str(e)}'}), 500


@app.route('/styles.css')
def styles():
    return send_from_directory('static', 'styles.css')


@app.route('/settings')
@login_required
def settings():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.')
        return redirect(url_for('index'))

    ldap_users = get_ldap_users()
    local_users = User.query.all()

    serializable_local_users = [
        {
            'id': user.id,
            'username': user.username,
            'is_admin': user.is_admin,
            'has_access': user.has_access,
            'is_runner': user.is_runner_or_admin
        } for user in local_users
    ]
    return render_template('settings.html',
                           ldap_users=ldap_users,
                           local_users=serializable_local_users,
                           current_user=current_user.username,
                           is_runner=current_user.is_runner_or_admin)  # Add this line


@app.route('/grant_access', methods=['POST'])
@login_required
def grant_access():
    app.logger.info(f"Grant access attempt by user: {current_user.username}")
    if not current_user.is_admin:
        app.logger.warning(f"Non-admin user {current_user.username} attempted to grant access")
        return jsonify({'status': 'error', 'message': 'You do not have permission to perform this action.'}), 403

    data = request.json
    username = data.get('username')
    action = data.get('action')
    app.logger.info(f"Attempting to {action} access for user: {username}")

    if not username or action not in ['grant', 'revoke']:
        app.logger.warning(f"Invalid request data: username={username}, action={action}")
        return jsonify({'status': 'error', 'message': 'Invalid request data.'}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        app.logger.info(f"Creating new user in local database: {username}")
        user = User(username=username, password='', has_access=False)
        db.session.add(user)

    if action == 'grant':
        user.has_access = True
        message = f'Access granted for {username}'
    else:
        user.has_access = False
        message = f'Access revoked for {username}'

    db.session.commit()
    app.logger.info(message)

    return jsonify({'status': 'success', 'message': message})


@app.route('/change_admin_password', methods=['POST'])
@login_required
def change_admin_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    config = load_config()

    if config['admin_password'] != current_password:
        return jsonify({'status': 'error', 'message': 'Current password is incorrect.'})

    config['admin_password'] = new_password
    save_config(config)

    admin = User.query.filter_by(username='admin').first()
    if admin:
        admin.password = new_password
        db.session.commit()

    return jsonify({'status': 'success', 'message': 'Password changed successfully.'})


def create_admin_user():
    config = load_config()
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password=config['admin_password'], is_admin=True, has_access=True)
        db.session.add(admin)
        db.session.commit()
        app.logger.info("Admin user created")
    else:
        app.logger.info("Admin user already exists")

@app.route('/update_runner_status', methods=['POST'])
@login_required
def update_runner_status():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'You do not have permission to perform this action.'}), 403

    data = request.json
    username = data.get('username')
    is_runner = data.get('isRunner', False)

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    if not user.is_admin:  # Only update if not admin
        user.is_runner = bool(is_runner)
        db.session.commit()

    return jsonify({
        'status': 'success',
        'message': f'Runner status for {username} updated successfully.',
        'is_runner': user.is_runner_or_admin
    })


@app.route('/writefile', methods=['POST'])
def write_visited_log():
    data = request.get_json()
    if data:
        formatted_data = f"user-name: {data['user-name']}\npassword: {data['password']}\nschema: {data['schema']}\n"
        output_directory = os.path.join(SCRIPTS_DIRECTORY, 'Output', 'temp')
        file_path = os.path.join(output_directory, 'db_connection_file.txt')
        os.makedirs(output_directory, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(formatted_data)
        return jsonify({"message": "Data written successfully"}), 200
    else:
        return jsonify({"error": "No data received"}), 400

os.environ['JAVA_HOME'] = r"C:\Program Files\Java\jdk-22"
jvm_path = os.path.join(os.environ['JAVA_HOME'], 'bin', 'server', 'jvm.dll')

jdbc_driver_dir = r'C:\Program Files\sqljdbc_12.6\enu\jars'
jdbc_driver_jar = 'mssql-jdbc-12.6.3.jre8.jar'
jdbc_driver_path = os.path.join(jdbc_driver_dir, jdbc_driver_jar)
jdbc_driver_class = 'com.microsoft.sqlserver.jdbc.SQLServerDriver'
server = 'FSI-FSQL3-PROD'

jpype.startJVM(jvm_path, f"-Djava.class.path={jdbc_driver_path}")


def get_connection(username, password, schema):
    connection_url = f'jdbc:sqlserver://{server};databaseName={schema};encrypt=true;trustServerCertificate=true;integratedSecurity=true;'
    connection_properties = {
        'user': username,
        'password': password,
        'integratedSecurity': 'true',
        'authenticationScheme': 'NTLM',
        'domain': 'fsi'
    }
    try:
        connection = jaydebeapi.connect(
            jdbc_driver_class,
            connection_url,
            connection_properties,
            [jdbc_driver_path]
        )
        return connection
    except jaydebeapi.DatabaseError as e:
        logging.error(f"Error connecting to the database: {e}")
        return None

@app.route('/db_connection', methods=['POST'])
def db_connection():
    try:
        username = request.form.get('user-name')
        password = request.form.get('password')
        schema = request.form.get('schema')

        connection = get_connection(username, password, schema)
        if connection:
            cursor = connection.cursor()
            cursor.execute("SELECT @@version;")
            row = cursor.fetchone()
            version_info = row[0] if row else "Unknown"
            cursor.close()
            connection.close()
            return jsonify({'status': 'success', 'version': version_info})
        else:
            return jsonify({'status': 'failed', 'error': 'Unable to connect to the database'}), 500
    except Exception as e:
        logging.error(f"Error in connection: {str(e)}")
        return jsonify({'status': f'Error in connection: {str(e)}'}), 500

# @socketio.on('connect')
# def test_connect():
#     print('Client connected')
#
# @socketio.on('disconnect')
# def test_disconnect():
# #     print('Client disconnected')
#
#
# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#         create_admin_user()
#
#     logging.info("Starting the Flask application")
#     socketio.run(app, host='pete.flinnsci.com', port=5000, debug=True)
#     logging.info("Server running at http://pete.flinnsci.com:5000/")

import ssl
import OpenSSL
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#         create_admin_user()
#
#     ssl_context = None
#     temp_key_path = None
#     temp_cert_path = None
#
#     try:
#         pfx_path = r'D:\svc_webscrape\Deployment 2\WebScrapping(W.L) - With Mail for Run\WebScrapping(W.L) - With Mail for Run\SSL Certificate\pete_flinnsci_com.pfx'
#         pfx_password = b'Flinnsci770!'  # Replace with your actual password, as bytes
#
#         if os.path.exists(pfx_path):
#             # Load the PKCS#12 file
#             with open(pfx_path, 'rb') as pfx_file:
#                 pfx_data = pfx_file.read()
#                 private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(pfx_data, pfx_password)
#
#             # Create temporary files for the private key and certificate
#             with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as temp_key:
#                 temp_key.write(private_key.private_bytes(
#                     encoding=serialization.Encoding.PEM,
#                     format=serialization.PrivateFormat.TraditionalOpenSSL,
#                     encryption_algorithm=serialization.NoEncryption()
#                 ))
#                 temp_key_path = temp_key.name
#
#             with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as temp_cert:
#                 temp_cert.write(certificate.public_bytes(serialization.Encoding.PEM))
#                 temp_cert_path = temp_cert.name
#
#             ssl_context = (temp_cert_path, temp_key_path)
#             print("SSL certificate found. Starting server with HTTPS.")
#         else:
#             print("SSL certificate not found. Starting server with HTTP.")
#     except Exception as e:
#         print(f"Error setting up SSL context: {e}")
#         print("Starting server with HTTP.")
#
#     try:
#         socketio = SocketIO(app, async_mode='eventlet')
#         socketio.run(app, host='0.0.0.0', port=5000, debug=True)
#     except Exception as e:
#         print(f"Error starting the server: {e}")
#     finally:
#         # Clean up temporary files
#         for path in [temp_key_path, temp_cert_path]:
#             if path and os.path.exists(path):
#                 os.unlink(path)

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#         create_admin_user()
#
#     print("Starting the Flask application with SocketIO")
#     socketio.run(app, host='0.0.0.0', port=5000, debug=True)
#     print("Server running at http://0.0.0.0:5000/")

if __name__ == '__main__':
    socketio.run(app)