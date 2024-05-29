from todoist_api_python.api import TodoistAPI

api = TodoistAPI("376f6ca4763413e176fd2a0eadd30af37f44cbea")

try:
    tasks = api.get_tasks(project_id=2322606786)
    print(tasks)
except Exception as error:
    print(error)
