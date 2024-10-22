from django.contrib import admin
from .models import User, APIKey, ExampleModel

# Register your models here.

admin.site.register(User)
admin.site.register(APIKey)
admin.site.register(ExampleModel)