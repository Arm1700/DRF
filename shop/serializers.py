from rest_framework import serializers
from .models import Post, PostImage, validate_image_file_extension
from django.contrib.staticfiles.storage import staticfiles_storage
from django.core.exceptions import ValidationError


class RestrictedImageExtensionValidator:
    def __init__(self, allowed_extensions):
        self.allowed_extensions = allowed_extensions

    def __call__(self, value):
        extension = value.name.split('.')[-1]
        if not extension.lower() in self.allowed_extensions:
            raise ValidationError(
                'File type not supported. Allowed extensions are: {}'.format(', '.join(self.allowed_extensions)))


def validate_image_type(value):
    supported_types = ['png', 'jpg', 'jpeg']
    if not value.content_type.lower() in ['image/png', 'image/jpeg', 'image/jpg']:
        raise serializers.ValidationError('Invalid image type. Only PNG, JPG and JPEG images are supported.')
    elif value.name.split('.')[-1] not in supported_types:
        raise serializers.ValidationError('Invalid image type. Only PNG, JPG and JPEG images are supported.')


class ImageField(serializers.ImageField):
    def to_representation(self, value):
        if not value:
            return None

        filename = staticfiles_storage.url(value.name)

        return filename.split('/')[-1]


class PostImageSerializer(serializers.ModelSerializer):
    image = ImageField()

    class Meta:
        model = PostImage
        fields = ['id', 'image_post', 'image']


class PostSerializer(serializers.ModelSerializer):
    images = PostImageSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=ImageField(max_length=100000, allow_empty_file=False, use_url=False, validators=[validate_image_file_extension]),
        write_only=True
    )
    username = serializers.ReadOnlyField(source='user.username')
    likes = serializers.SerializerMethodField()
    total_likes = serializers.SerializerMethodField()
    description = serializers.CharField(default='', allow_blank=True)

    class Meta:
        model = Post
        fields = ['id', 'username',  'uploaded_images', 'description', 'created_at', 'likes', 'total_likes', 'images']
        read_only_fields = ['id', 'created_at', 'likes', 'total_likes', 'username']

    @staticmethod
    def get_likes(obj):
        return obj.likes.values_list('username', flat=True)

    @staticmethod
    def get_total_likes(obj):
        return obj.likes.count()

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        request = self.context.get('request')
        if request and request.username.is_authenticated:
            representation['likes'] = instance.likes.filter(id=request.username.id).exists()
        return representation

    def validate_uploaded_images(self, value):
        for image in value:
            validate_image_type(image)
        return value

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images')
        image_post = Post.objects.create(**validated_data)
        for image in uploaded_images:
            validate_image_type(image)
            new_image_post = PostImage.objects.create(image_post=image_post, image=image)
            new_image_post.caption = f"Caption for image {new_image_post.id}"
            new_image_post.save()

        return image_post
