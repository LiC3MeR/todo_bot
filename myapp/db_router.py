class MyAppRouter:
    def db_for_read(self, model, **hints):
        if model._meta.app_label == 'nlu_app':
            return 'nlu'
        elif model._meta.app_label == 'test_app':
            return 'test'
        return 'default'

    def db_for_write(self, model, **hints):
        if model._meta.app_label == 'nlu_app':
            return 'nlu'
        elif model._meta.app_label == 'test_app':
            return 'test'
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        db_list = ('nlu', 'test', 'default')
        if obj1._state.db in db_list and obj2._state.db in db_list:
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == 'nlu_app':
            return db == 'nlu'
        elif app_label == 'test_app':
            return db == 'test'
        return db == 'default'