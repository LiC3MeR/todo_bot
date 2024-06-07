# myapp/admin.py
from django.contrib import admin
from .models import User, Task, Comment
from myapp.models import User

admin.site.register(User)
admin.site.register(Task)
admin.site.register(Comment)
