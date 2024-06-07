from django.contrib.auth.models import AbstractUser, Group
from django.db import models

class User(AbstractUser):
    role = models.CharField(max_length=80)

    class Meta:
        app_label = 'myapp'  # Ensure this matches your app name

    def __str__(self):
        return self.username

class UserGroups(models.Model):
    user = models.ForeignKey('myapp.User', on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)

    class Meta:
        app_label = 'myapp'  # Ensure this matches your app name

    def __str__(self):
        return self.content

class Task(models.Model):
    task_id = models.CharField(max_length=80, unique=True)
    content = models.CharField(max_length=200)
    priority = models.IntegerField()
    description = models.TextField()
    project_id = models.BigIntegerField(null=True)
    status = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    assigned_to = models.ForeignKey(User, related_name='tasks', on_delete=models.SET_NULL, null=True)
    duration = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.content


class Comment(models.Model):
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    task = models.ForeignKey(Task, related_name='comments', on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name='comments', on_delete=models.CASCADE)

    def __str__(self):
        return f"{self.user.username} - {self.group.name}"