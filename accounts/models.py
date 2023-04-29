from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from rest_framework.exceptions import ValidationError
from datetime import datetime, timedelta
from django.utils import timezone
from .managers import CustomUserManager


class User(AbstractBaseUser):
    DoesNotExist = None
    email = models.EmailField(verbose_name="email", max_length=68, unique=True)
    username = models.CharField(verbose_name="username", max_length=36, unique=True)
    last_login = models.DateTimeField(verbose_name='last login', auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    first_name = models.CharField(max_length=60, null=True, blank=True)
    last_name = models.CharField(max_length=30, null=True, blank=True)
    profile_pic = models.ImageField(upload_to='image', blank=True, null=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', "first_name", "last_name"]

    objects = CustomUserManager()

    def __str__(self):
        return f"{self.username} id {self.id}"

    def has_perm(self, perm, obj=None):
        return self.is_admin

    @staticmethod
    def has_module_perms(app_label):
        return True


class RefreshTokenModel(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Refresh token for {self.user.username}"

    def verify(self):
        if timezone.now() > self.created_at + timedelta(days=7):
            raise ValueError("Token has expired.")


class FriendRequest(models.Model):
    DoesNotExist = None
    objects = None
    from_user = models.ForeignKey(
        User, related_name='friend_requests_sent', on_delete=models.CASCADE)
    to_user = models.ForeignKey(
        User, related_name='friend_requests_received', on_delete=models.CASCADE)
    message = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)

    class Meta:
        unique_together = ('from_user', 'to_user')

    def __str__(self):
        return f'{self.from_user} to {self.to_user}'

    def clean(self):
        if self.from_user == self.to_user:
            raise ValidationError('You cannot send a friend request to yourself.')


class Friendship(models.Model):
    DoesNotExist = None
    objects = None
    from_user = models.ForeignKey(
        User, related_name='friendship_initiated', on_delete=models.CASCADE)
    to_user = models.ForeignKey(
        User, related_name='friendship_received', on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('from_user', 'to_user')

    def __str__(self):
        return f'{self.from_user} to {self.to_user}'

    @staticmethod
    def get(from_user, to_user):
        try:
            return Friendship.objects.get(from_user=from_user, to_user=to_user)
        except Friendship.DoesNotExist:
            return None
