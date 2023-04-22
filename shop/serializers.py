from rest_framework import serializers
from .models import Post, PostImage


class PostImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PostImage
        fields = ['id', 'image_post', 'image']


class PostSerializer(serializers.ModelSerializer):
    images = PostImageSerializer(many=True, read_only=True)
    uploaded_images = serializers.ListField(
        child=serializers.ImageField(max_length=100000, allow_empty_file=False, use_url=False),
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

    def create(self, validated_data):
        uploaded_images = validated_data.pop('uploaded_images')
        image_post = Post.objects.create(**validated_data)
        for image in uploaded_images:
            new_image_post = PostImage.objects.create(image_post=image_post, image=image)
            new_image_post.caption = f"Caption for image {new_image_post.id}"
            new_image_post.save()

        return image_post
