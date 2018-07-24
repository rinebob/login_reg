from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^index$', views.index),
    url(r'^show$', views.show),
    url(r'^login$', views.login),
    url(r'^register$', views.register),
    url(r'^rest$', views.rest),
    url(r'^logout$', views.logout),
    

]

