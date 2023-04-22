from django.contrib import admin
from . import models

admin.site.register(models.User)
admin.site.register(models.FriendRequest)
admin.site.register(models.Friendship)
