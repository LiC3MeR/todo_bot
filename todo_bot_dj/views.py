# myapp/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from myapp.models import User, Task, Comment, UserGroups
from myapp.forms import CustomUserCreationForm, CustomAuthenticationForm

@login_required
def comments(request, task_id):
    task = get_object_or_404(Task, id=task_id)

    if request.method == 'POST':
        content = request.POST.get('comment_content')
        if content:
            try:
                comment = Comment(content=content, user=request.user, task=task)
                comment.save()

                # Отправка уведомления в Telegram
                send_telegram_message(f'Добавлен новый комментарий от пользователя {request.user.username} к задаче {task.task_id}:\n {content}')

                return JsonResponse({
                    'username': comment.user.username,
                    'content': comment.content,
                    'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }, status=201)
            except Exception as e:
                print(e)
                return JsonResponse({'error': 'Failed to add comment'}, status=400)

    elif request.method == 'GET' and request.is_ajax():
        comments = [{
            'username': comment.user.username,
            'content': comment.content,
            'created_at': comment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        } for comment in task.comments.all() if comment.user]  # Проверяем, что comment.user не None
        return JsonResponse(comments, safe=False)

    return render(request, 'comments.html', {'task': task, 'comments': task.comments.all()})

@login_required
def update_task(request, task_id):
    task = get_object_or_404(Task, id=task_id)

    if request.method == 'POST':
        try:
            content = request.POST.get('content')
            description = request.POST.get('description')
            assigned_to = request.POST.get('assigned_to')

            if content:
                task.content = content
            if description:
                task.description = description
            if assigned_to:
                task.assigned_to = assigned_to

            task.save()

            return JsonResponse({"message": "Задача успешно обновлена"})
        except Exception as error:
            print("Error updating task:", error)
            return JsonResponse({"error": str(error)}, status=500)

@login_required
def menu(request):
    return render(request, 'menu.html', {'user': request.user})

def reg(request):
    return render(request, 'reg.html', {'user': request.user})

@login_required
def create_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        role = request.POST.get('role')

        existing_user = User.objects.filter(username=username).first()
        if existing_user:
            messages.error(request, 'Пользователь с таким именем уже существует')
            return redirect('users')

        if not (username and password and role):
            return JsonResponse({'error': 'Не все поля были заполнены'}, status=400)

        hashed_password = make_password(password)
        new_user = User(username=username, password=hashed_password, role=role)
        new_user.save()

        messages.success(request, 'Пользователь успешно создан')
        return redirect('users')

@login_required
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = User.objects.filter(username=username).first()

        if user and user.check_password(password):
            login(request, user)
            return redirect()
        else:
            messages.error(request, 'Неверное имя пользователя или пароль')

    return render(request, 'login.html')

@login_required
def admin_panel(request):
    if request.user.role != 'admin':
        return redirect('/')  # Возможно, стоит добавить страницу доступа запрещено (403)
    return render(request, 'admin_panel.html')

@login_required
def change_role(request):
    if request.method == 'POST':
        data = request.POST.dict()
        user_id = data.get('user_id')
        new_role = data.get('new_role')

        user = User.objects.filter(id=user_id).first()
        if user:
            user.role = new_role
            user.save()
            return JsonResponse({"success": True, "message": "Роль успешно изменена."})
        else:
            return JsonResponse({"success": False, "message": "Пользователь не найден."}, status=404)

@login_required
def logout_view(request):
    logout(request)
    return redirect('/login')