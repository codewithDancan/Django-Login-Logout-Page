from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import PasswordChangeForm
@login_required(login_url='login')
def home(request):
    return render(request, 'home.html')

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('/')
        else:
            messages.info(request, 'Credentials Invalid')
            return redirect('login')
    else:
        return render(request, 'login.html')

def signup(request):
    if request.method == 'POST':
        email = request.POST['email']
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password2']
        if password == password2:
            if User.objects.filter(username=username):
                messages.info(request, 'Username Taken')
                return redirect('signup')
            elif User.objects.filter(email=email):
                messages.info(request, 'Email Already Taken')
                return redirect('signup')
            else:
                new_user = User.objects.create_user(username=username, email=email, password=password)
                new_user.save()
                # log user in
                user_login = auth.authenticate(username=username,password=password)
                auth.login(request, user_login)
                return redirect('login')
        else:
            messages.info(request, 'Password Not Matching')
            return redirect(request, 'signup')
    else:
        return render(request, 'signup.html')
    
@login_required(login_url='login')
def reset(request):
    if request.method == 'POST':
        current_password = request.POST.get('password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        user = authenticate(username=request.user.username, password=current_password)

        if user is not None:
            if new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)
                auth.login(request, user)# optional re-login after password change 
                messages.success(request, 'Your Password Was Successfully Updated')
                return redirect('reset')
            else:
                messages.error(request, 'Password Not Matching')
        else:
            messages.error(request, 'Invalid Credentials')
    return render(request, 'reset.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    return render(request, 'login')
    
