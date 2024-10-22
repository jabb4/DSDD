from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.hashers import check_password

import uuid

from .forms import *
from .models import User, APIKey

## Task Imports ##
from .tasks import example_task

## This is an example homepage view that tests the background task
def homepage_view(request):
    page = "homepage"
    user = request.user
    print(user)
    logged_in = user.is_authenticated
    print(logged_in)
    error_message = None
    success_message = None

    if logged_in:
        example_task.delay()

    context = {
        "page": page, "user": user, "logged_in": logged_in, "error_message": error_message, "success_message": success_message,

    }
    return render(request, "homepage.html", context=context)

def login_view(request):
    page = "login"
    user = request.user
    logged_in = user.is_authenticated
    error_message = None
    success_message = None

    if logged_in:
        return redirect("account")

    form = UserLoginForm

    try:
        if request.method == "POST" and request.POST["password"] and request.POST["username"] and request.POST["login"]:
            username = request.POST["username"]
            password = request.POST["password"]
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return redirect("account")
            else:
                error_message = "Username OR Password is not correct"
    except KeyError:
        pass

    context = {
        "page": page, "user": user, "logged_in": logged_in, "error_message": error_message, "success_message": success_message,
        "form":form, 
    }
    return render(request, "login.html", context=context)


def logout_view(request):
    page = "logout"
    user = request.user
    logged_in = user.is_authenticated
    error_message = None
    success_message = None

    if logged_in:
        logout(request)

    return redirect("login")

def register_view(request):
    page = "register"
    user = request.user
    logged_in = user.is_authenticated
    error_message = None
    success_message = None

    if logged_in:
        return redirect("account")

    form=CreateUserForm

    if request.method == "POST":
        try:
            if request.POST["username"] and request.POST["password1"] and request.POST["password2"] and request.POST["register"]:
                form=CreateUserForm(request.POST)
                username = request.POST["username"]
                password1 = request.POST["password1"]
                password2 = request.POST["password2"]

                ### Check if username if taken ###
                if User.objects.filter(username=username):
                    error_message = "Username is taken!"
                
                if username == "AnonymousUser":
                    error_message = "Username is Forbidden!"

                ### Check Password ###
                if not password1 == password2 and not error_message:
                    error_message = "Passwords do not match!"

                if not error_message:
                    user = form.save()
                    user.save()
                    login(request, user)
                    return redirect("account")
        except KeyError:
            error_message = "Fill in all fields"

    context = {
        "page": page, "user": user, "logged_in": logged_in, "error_message": error_message, "success_message": success_message,
        "form":form, 
    }
    return render(request, "register.html", context=context)

def account_view(request):
    page = "account"
    user = request.user
    logged_in = user.is_authenticated
    error_message = None
    success_message = None

    if not logged_in:
        return redirect("login")

    api_keys = APIKey.objects.filter(user=user)

    delete_user_page = False
    form = None


### Check if method is POST ###
    if request.method == "POST":

### API Keys ###
    ## New API Key ##
        try:
            if request.POST["new_api_key"]:
                APIKey.objects.create(user=user, api_key=str(uuid.uuid4()).replace("-", ""))
                return redirect("account")
        except KeyError:
            pass
    
    ## Delete API Key ##
        try:
            if request.POST["delete_api_key"]:
                APIKey.objects.get(user=user, id=request.POST["api_key_id"]).delete()
                return redirect("account")
        except KeyError:
            pass

### Update Account Info ###
    ## Update Username ##
        try:
            if request.POST["update_username"] and request.POST["update_username_password"] and request.POST["submit_username"]:
                new_username = request.POST["update_username"]
                current_password = request.POST["update_username_password"]
                test_username = User.objects.filter(username=new_username)
                if test_username:
                    error_message = "Username is taken!"
                elif new_username == "AnonymousUser":
                    error_message = "Username is Forbidden!"
                elif check_password(current_password, user.password): 
                    user.username = new_username
                    user.save()
                    success_message = "Username Updated!"
                else:
                    error_message = "Incorrect Password!"
        except KeyError:
            pass
    
    ## Update Password ##
        try:
            if request.POST["updated_password"] and request.POST["repeat_updated_password"] and request.POST["updated_password_password"] and request.POST["submit_password"]:
                new_password1 = request.POST["updated_password"]
                new_password2 = request.POST["repeat_updated_password"]
                current_password = request.POST["updated_password_password"]
                if not new_password1 == new_password2:
                    error_message = "Passwords do not match!"
                else:
                    if check_password(current_password, user.password):
                        user.set_password(new_password1)
                        user.save()
                        update_session_auth_hash(request, user)
                        success_message = "Password Updated!"
                    else:
                        error_message = "Incorrect Password!"
        except KeyError:
            pass

### Delete User ###
    ## Check for delete button submit ##
        try:
            if request.POST["delete_user"]:
                page = "edit_user_child"
                delete_user_page = True
        except KeyError:
            pass
    
    ## Delete User comfirmation ##
        try:
            if request.POST["delete_user_password"] and request.POST["delete_user_password_submit"]:
                current_password = request.POST["delete_user_password"]
                if check_password(current_password, user.password):
                    user.delete()
                    return redirect("login")
                else:
                    page = "edit_user_child"
                    delete_user_page = True
                    error_message = "Incorrect Password!"
        except KeyError:
            pass

    context = {
        "page": page, "user": user, "logged_in": logged_in, "error_message": error_message, "success_message": success_message,
        "form": form, "delete_user_page": delete_user_page, "api_keys": api_keys,
    }
    return render(request, "account.html", context=context)