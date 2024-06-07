# myapp/urls.py
from django.urls import path, include
from django.contrib import admin
from . import views
from .views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('task/<int:task_id>/comments', views.comments, name='comments'),
    path('update_task/<int:task_id>', views.update_task, name='update_task'),
    path('menu/', views.menu, name='menu'),
    path('register/', views.reg, name='reg'),
    path('create_user/', views.create_user, name='create_user'),
    path('login/', views.login, name='login'),
    path('admin_panel/', views.admin_panel, name='admin_panel'),
    path('change_role/', views.change_role, name='change_role'),
    path('logout/', views.logout, name='logout'),
]
