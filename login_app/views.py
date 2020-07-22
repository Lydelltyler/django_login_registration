from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import User
import bcrypt


########## HOME PAGE
def index(request):
    return render(request, "index.html")

########## LOGIN AREA
def login(request):
    userEmail = User.objects.filter(email=request.POST['email'])
    print(request.POST)
    pass1 = False
    emai1 = False

    if userEmail:
        emai1 = True
        logged_user = userEmail[0]
        password_check = bcrypt.checkpw(
            request.POST['password'].encode(), logged_user.password.encode())
        if password_check:
            pass1 = True
            request.session['userid'] = logged_user.id
            request.session['login'] = True
            return redirect('/success')

    context = {
        'password': pass1,
        'email': emai1
    }
    errors = User.objects.login_validator(context)
    if len(errors) > 0:
        for key, val in errors.items():
            messages.error(request, val)

    return redirect('/')

########## REGISTRATION AREA
def register(request):
    errors = User.objects.register_validator(request.POST)
    print(request.POST)
    if len(errors) > 0:
        for key, val in errors.items():
            messages.error(request, val)
    else:
        password = request.POST['password']
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        print(pw_hash)
        registered_user = User.objects.create(
            first_name=request.POST['first_name'], last_name=request.POST['last_name'], email=request.POST['email'], password=pw_hash)
        request.session['userid'] = registered_user.id
        request.session['register'] = True
        return redirect('/success')
    return redirect('/')

########## SUCCESS PAGE AREA
def success(request):
    print(request.session['login'])
    user_id = request.session['userid']
    if request.session['login'] == True:
        context = {
            'user': User.objects.get(id = user_id),
            'login': 'logged in' 
        }
    elif request.session['register'] == True:
        context = {
            'user': User.objects.get(id = user_id),
            'register': 'registered' 
        }
    
    return render(request, "success.html", context)

########## LOGOUT FUNCTION
def logout(request):
    request.session['userid'] = None
    request.session['register'] = False
    request.session['login'] = False
    return redirect('/')