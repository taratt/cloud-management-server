"""
@author: Tara Saba
"""

import virtualbox
from virtualbox.library import MachineState, CloneMode, CloneOptions
from flask import Flask, request, jsonify, make_response
import subprocess
import jwt
import datetime
import time
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.utils import secure_filename
import paramiko
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vboxcloudserver'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'C:\\Users\\taratt\\PycharmProjects\\cloud-management-server'
database = SQLAlchemy(app)

vbox = virtualbox.VirtualBox()
class User(database.Model):
    username = database.Column(database.String(255), primary_key=True)
    password = database.Column(database.String(255), nullable=False)
    admin_access = database.Column(database.String(255))

def initialize_db():
    admin = User(username ='admin', password = 'adminpass', admin_access = 'admin')
    user1 = User(username ='user1', password ='user1pass',admin_access ='user')
    try:
        database.session.add(admin)
        database.session.add(user1)
        database.session.commit()
    except:
        database.session.rollback()

database.create_all()
database.session.commit()
initialize_db()

def validate_login(username, password):
    user = User.query.filter_by(username= username).first()
    if user:
        if user.password == password:
            return True, user.admin_access
        else:
            return False,None
    else:
        newUser = User(username=username, password=password, admin_access='user')
        try:
            database.session.add(newUser)
            database.session.commit()
        except:
            database.session.rollback()
            return False, None
        return True, newUser.admin_access

def create_token(username, access):
    token = jwt.encode({'username': username, 'access': access,'exp': datetime.datetime.utcnow()+ datetime.timedelta(minutes=30)},app.config['SECRET_KEY'], algorithm="HS256")
    return token


def validate_token(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
    except:
        return False
    return True

def authentication(function):
    @wraps(function)
    def token_and_login(*args, **kwargs):
        headers = request.headers
        authorizarion_header = headers.get('Authorization')
        if authorizarion_header:
            try:
                token = authorizarion_header.split(" ")[1]
            except:
                return jsonify({'authorization': 'Failed', 'message': 'Malformed Authorization header'}), 401
            authorized = validate_token(token)
            if authorized:
                return function(*args, **kwargs)
            else:
                return jsonify({'authorization': 'Failed', 'message': 'Invalid token'}), 401

        else:
            try:
                body = request.get_json(force= True)
                username = body.get('username')
                password = body.get('password')
                isLoginValid, access = validate_login(username, password)
                if isLoginValid:
                    created_token = create_token(username,access)
                    return jsonify({'token': created_token})
                else:
                    return jsonify({'authorization': 'Failed', 'message': 'Login required, wrong password'}), 403
            except:
                return jsonify({'authorization': 'Failed', 'message': 'Login required, username or password was not provided'}), 403
    return token_and_login



@app.route('/', methods=['GET', 'POST'])
@authentication
def request_handler():
    headers = request.headers
    authorizarion_header = headers.get('Authorization')
    content_type = headers.get('content-type')
    access = jwt.decode(authorizarion_header.split(' ')[1], app.config['SECRET_KEY'],algorithms=["HS256"]).get('access')
    if content_type == "application/json":
        body = request.get_json()
        command = body.get('command')
        vmName = body.get('vmName')
        sourceVmName = body.get('sourceVmName')
        destVmName = body.get('destVmName')
        if command == None:
            return jsonify({'message': 'Command was not provided'}), 400
        if command == 'status':
            if access_check(access, vmName):
                return jsonify({"message": "Access Denied"}), 403
            else:
                if vmName == None:
                    details = get_status()
                    return jsonify({"command": "status", "details": str(details)})
                else:
                    return jsonify({"command": "status", "vmName": vmName,"state": get_vm_status(vmName)})
        if command == 'on':
            if vmName == None:
                return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
            else:
                if access_check(access, vmName):
                    return jsonify({"message": "Access Denied"}), 403
                else:
                    if launch_machine(vmName):
                        return jsonify({'command': 'on', 'vmName':vmName, 'status':'powering on'})
                    else:
                        return jsonify({'message': 'Failed to launch the virtual machine'})
        if command == 'off':
            if vmName == None:
                return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
            else:
                if access_check(access, vmName):
                    return jsonify({"message": "Access Denied"}), 403
                else:
                    if poweroff_machine(vmName):
                        return jsonify({'command': 'off', 'vmName': vmName, 'status': 'powering off'})
                    else:
                        return jsonify({'message': 'Failed to power off the virtual machine'})

        if command == 'clone':
            if sourceVmName == None:
                return jsonify({'message': 'Source Virtual Machine\'s name was not provided'}), 400
            else:
                if access_check(access, sourceVmName):
                    return jsonify({"message": "Access Denied"}), 403
                else:
                    if clone_vm(sourceVmName,destVmName):
                        return jsonify({'command': 'clone', 'sourceVmName': sourceVmName, 'destVmName':destVmName, 'status': 'ok'})

                    else:
                        return jsonify({'message': 'Failed to clone the virtual machine'})

        if command == 'delete':
            if vmName == None:
                return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
            else:
                if access_check(access, vmName):
                    return jsonify({"message": "Access Denied"}), 403
                else:
                    if remove_vm(vmName):
                        return jsonify({'command': 'delete', 'vmName': vmName,'status': 'ok'})

                    else:
                        return jsonify({'message': 'Failed to remove the virtual machine'})

        if command == 'setting':
            cpu = body.get('cpu')
            ram = body.get('ram')
            if vmName == None:
                return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
            else:
                if access_check(access, vmName):
                    return jsonify({"message": "Access Denied"}), 403
                else:
                    if cpu == None and ram == None:
                        return jsonify({'message': 'Virtual Machine\'s ram and cpu settings were not provided'}), 400
                    else:
                        if config_vm(vmName, cpu, ram):
                            if ram != None and cpu!= None:
                                return jsonify({'command': 'setting', 'vmName': vmName,'cpu': cpu, 'ram':ram, 'status': 'ok'})
                            elif ram == None:
                                return jsonify({'command': 'setting', 'vmName': vmName, 'cpu': cpu,'status': 'ok'})
                            elif cpu == None:
                                return jsonify({'command': 'setting', 'vmName': vmName, 'ram': ram, 'status': 'ok'})
                        else:
                            return jsonify({'message': 'Failed to change the virtual machine\'s settings'})

        if command == 'execute':
            if vmName == None:
                return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
            else:
                if access_check(access, vmName):
                    return jsonify({"message": "Access Denied"}), 403
                else:
                    input = body.get('input')
                    if input == None:
                        return jsonify({'message': 'Input was not provided'}), 400
                    else:
                        response = execute(vmName, input)

                        if response:
                            return jsonify({'command': 'execute', 'vmName': vmName,'status': 'ok', 'response': response})

                        else:
                            return jsonify({'message': 'Failed to execute the command in virtual machine'})

        if command == 'transfer':
            originVM = body.get('originVM')
            destVM = body.get('destVM')
            originPath = body.get('originPath')
            destPath = body.get('destPath')
            if originVM == None or destVM==None:
                return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
            if originPath== None or destPath == None:
                return jsonify({'message': 'File path was not specified'}), 400
            else:
                if access_check(access, originPath):
                    return jsonify({"message": "Access Denied"}), 403
                else:

                     response = transfer(originVM, destVM, originPath, destPath)

                     if response:
                        return jsonify({'command': 'transfer', 'originVM': originVM, 'originPath':originPath,'destVM': destVM, 'destPath':destPath, 'status': 'ok'})

                     else:
                        return jsonify({'message': 'Failed to execute the command in virtual machine'})



    file = request.files['file']
    vmName = request.form['vmName']
    path = request.form['path']
    if vmName == None:
        return jsonify({'message': 'Virtual Machine\'s name was not provided'}), 400
    if file == None or file == "":
        return jsonify({'message': 'The file was not provided'}), 400
    if path == None or path == "":
        return jsonify({'message': 'The path was not provided'}), 400
    if access_check(access, vmName):
        return jsonify({"message": "Access Denied"}), 403
    response = upload(vmName, file, path)
    # return jsonify(response)
    if response:
        return jsonify({'command': 'upload', 'vmName': vmName, 'status': 'ok'})

    else:
        return jsonify({'message': 'Failed to upload the file on virtual machine'})




def access_check(access, parameter):
    if access == 'user' and parameter != 'VM1':
        return True
    return False

def status_map(status):
    if status == MachineState(10):
        return "powering on"
    if status == MachineState(11):
        return "powering off"
    if MachineState(5) <= status <= MachineState(18):
        return "On"
    return "off"

def get_status():
    details = []
    for machine in vbox.machines:
        vm = {}
        vm['vmName'] = machine.name
        vm['status'] = status_map(machine.state)
        details.append(vm)
    return details


def get_vm_status(vm):
    vm = vbox.find_machine(vm)
    return status_map(vm.state)

def launch_machine(vmName):
    try:
        session = virtualbox.Session()
        vm = vbox.find_machine(vmName)
        progress = vm.launch_vm_process(session, 'gui', [])

        return True
    except:
        return False

def poweroff_machine(vmName):
    try:
        vm = vbox.find_machine(vmName)
        session = vm.create_session()
        session.console.power_down()
        return True
    except:
        return False

def clone_vm(sourceVmName, destVmName):
     try:
        sourceVm = vbox.find_machine(sourceVmName)
        destVm = vbox.create_machine(name=destVmName, os_type_id="Ubuntu_64",settings_file="",groups=['/'],flags ="")
        progress= sourceVm.clone_to(destVm, CloneMode(3), [CloneOptions(4)])
        progress.wait_for_completion()
        vbox.register_machine(destVm)
        return True
     except:
         return False

def remove_vm(vmName):
    try:
        vm = vbox.find_machine(vmName)
        vm.remove(delete = True)
        return True
    except:
        return False


def config_vm(vmName, cpu, ram):
   try:
        powered_off = True
        if get_vm_status(vmName) == "on":
            powered_off = poweroff_machine(vmName)
        if powered_off:
            if cpu != None:
                subprocess.call(["vboxmanage", "modifyvm", vmName, "--cpus", str(cpu)])
            if ram!= None:
                subprocess.call(["vboxmanage", "modifyvm", vmName, "--memory", str(ram)])
            return True
        else:
            return powered_off
   except:
        return False

def execute(vmName, command):

    try:
        if get_vm_status(vmName) == "off":
            launch_machine(vmName)
            time.sleep(60)

        ip = subprocess.check_output(['vboxmanage', 'guestproperty', 'get', vmName,"/VirtualBox/GuestInfo/Net/0/V4/IP"]).decode('utf-8').split(' ')[1].splitlines()[0]
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username='vm1', password='1610')
        stdin, stdout, stderr = client.exec_command(command)
        outstr = stdout.read().decode("utf-8").split('\n')
        errorstr = stderr.read().decode("utf-8")
        client.close()
        if outstr != '':
            output =''
            for out in outstr:
                output += str(out)+' '
            return output
        return errorstr
    except:
            return False

def upload(vmName, file, path):
      try:
        if get_vm_status(vmName) == "off":
              launch_machine(vmName)
              time.sleep(120)

        file.save(secure_filename(file.filename))
        vm = vbox.find_machine(vmName)
        session = vm.create_session()
        guest = session.console.guest.create_session('vm1', '1610')

        progress= guest.copy_to_guest([app.config['UPLOAD_FOLDER']+'\\'+secure_filename(file.filename)],[], [], path)
        progress.wait_for_completion()
        guest.close()
        os.remove(secure_filename(file.filename))
        return True
      except:
         return False

def transfer(originVM, destVM, originPath, destPath):
    try:
        flag = False
        if get_vm_status(originVM) == "off":
            launch_machine(originVM)
            flag = True
        if get_vm_status(destVM) == "off":
            launch_machine(destVM)
            flag = True
        if flag:
            time.sleep(120)

        #file.save(secure_filename(file.filename))
        originVM = vbox.find_machine(originVM)
        originSession = originVM.create_session()
        originGuest = originSession.console.guest.create_session('vm1', '1610')
        filename = originPath.split('/')[len(originPath.split('/'))-1]
        progress = originGuest.file_copy_from_guest(originPath,app.config['UPLOAD_FOLDER'],[])
        progress.wait_for_completion()
        originGuest.close()

        destVM = vbox.find_machine(destVM)
        destSession = destVM.create_session()
        destGuest = destSession.console.guest.create_session('vm1', '1610')

        progress = destGuest.copy_to_guest([app.config['UPLOAD_FOLDER']+'\\'+filename],[], [], destPath)
        progress.wait_for_completion()
        originGuest.close()
        os.remove(app.config['UPLOAD_FOLDER']+'\\'+filename)

        return True
    except:
        return False

app.run()

