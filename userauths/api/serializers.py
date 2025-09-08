from rest_framework import serializers

from core import models as core_models


class AdminProfileSerializer(serializers.Serializer):
    username = serializers.CharField(source="user.username", required=False)
    email = serializers.EmailField(source="user.email", required=False)
    first_name = serializers.CharField(
        source="user.first_name", required=False, allow_blank=True
    )
    last_name = serializers.CharField(
        source="user.last_name", required=False, allow_blank=True
    )
    phone_number = serializers.IntegerField(
        source="user.phone_number", required=False, allow_null=True
    )
    address = serializers.CharField(required=False, allow_blank=True)
    profile_picture = serializers.ImageField(required=False)
    city = serializers.CharField(required=False, allow_blank=True)
    state = serializers.CharField(required=False)
    zipcode = serializers.IntegerField(required=False, allow_null=True)
    bio = serializers.CharField(required=False, allow_blank=True)

    def validate_phone_number(self, value):
        if value and len(str(value)) != 10:
            raise serializers.ValidationError("Phone number must be 10 digits.")
        return value

    def update(self, instance, validated_data):
        # Update related User Fields
        user_data = validated_data.pop("user", {})
        for attr, value in user_data.items():
            setattr(instance.user, attr, value)
        instance.user.save()

        # Handle profile picture explicitly
        profile_picture = validated_data.pop("profile_picture", None)
        if profile_picture:
            instance.profile_picture = profile_picture

        # Update other UserProfile Fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance


# With Serializer
class AdminDashboardSerializer(serializers.Serializer):
    total_category = serializers.IntegerField()
    total_products = serializers.IntegerField()
    total_customers = serializers.IntegerField()
    total_orders = serializers.IntegerField()


class AdminCustomerSerializer(serializers.Serializer):
    id = serializers.IntegerField(required=False)  # Include the user ID
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    phone_number = serializers.IntegerField(required=False, allow_null=True)
    address = serializers.CharField(
        source="userprofile.address", required=False, allow_blank=True
    )  # Assuming address is part of UserProfile
    profile_picture = serializers.ImageField(
        source="userprofile.profile_picture", required=False
    )  # Assuming profile_picture is part of UserProfile
    city = serializers.CharField(
        source="userprofile.city", required=False, allow_blank=True
    )  # Assuming city is part of UserProfile
    state = serializers.CharField(
        source="userprofile.state", required=False
    )  # Assuming state is part of UserProfile
    zipcode = serializers.CharField(
        source="userprofile.zipcode", required=False, allow_null=True
    )  # Assuming zipcode is part of UserProfile
    bio = serializers.CharField(
        source="userprofile.bio", required=False, allow_blank=True
    )  # Assuming bio is part of UserProfile


class AdminCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = core_models.Category
        fields = "__all__"


class AdminProductSerializer(serializers.ModelSerializer):
    category = serializers.PrimaryKeyRelatedField(
        queryset=core_models.Category.objects.all()
    )
    full_name = serializers.SerializerMethodField(read_only=True)
    category_name = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = core_models.Product
        fields = [
            "id",
            "title",
            "selling_price",
            "discounted_price",
            "description",
            "brand",
            "product_image",
            "category",
            "full_name",
            "category_name",
        ]
        read_only_fields = ["user"]

    def create(self, validated_data):
        validated_data["user"] = self.context["request"].user
        return super().create(validated_data)

    def get_full_name(self, obj):
        first_name = obj.user.first_name or ""
        last_name = obj.user.last_name or ""
        return f"{first_name} {last_name}".strip()

    def get_category_name(self, obj):
        try:
            return obj.category.title
        except AttributeError:
            return None

    def to_representation(self, instance):
        """Customize the representation of the object (GET only)"""
        representation = super().to_representation(instance)
        request = self.context.get("request")

        if request and request.method == "GET":
            # Remove the raw category ID from the response
            representation.pop("category", None)
        return representation
