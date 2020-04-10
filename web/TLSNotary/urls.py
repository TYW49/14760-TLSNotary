from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('generate-proof', views.generate_proof_action, name='generate-proof'),
    path('verify-proof', views.verify_proof_action, name='verify-proof'),
]