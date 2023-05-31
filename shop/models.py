from django.db import models
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()


class Post(models.Model):
    DoesNotExist = None
    objects = None
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    likes = models.ManyToManyField(User, related_name='liked_posts', blank=True)

    def __str__(self):
        return f"Post by {self.user.username} id {self.id}"

    def total_likes(self):
        return self.likes.count()

    def get_likers(self):
        return self.likes.all()

    def like_post(self, user):
        if user in self.likes.all():
            self.likes.remove(user)
            return False
        else:
            self.likes.add(user)
            return True


def validate_image_file_extension(value):
    ext = value.name.split('.')[-1].lower()
    if ext not in ['jpg', 'jpeg', 'png']:
        raise ValidationError("Unsupported file extension.")


class PostImage(models.Model):
    DoesNotExist = None
    objects = None
    image_post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='img', default='', null=True, blank=True, validators=[validate_image_file_extension])

    def __str__(self):
        return f"Image by {self.image_post.user.username} id {self.image_post.user.id} for post {self.image_post.id} with id {self.id}"
