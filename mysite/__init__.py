try:
    from .celery import app as celery_app
    __all__ = ('celery_app',)
except ImportError:
    pass  # Celery no instalado — funciona sin cola de tareas
