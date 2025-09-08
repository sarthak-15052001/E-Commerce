import re

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.db.models import F, Sum
from django.utils import timezone
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from core import models as core_models
from userauths import models as user_models


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = user_models.User
        fields = [
            "username",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "password",
            "confirm_password",
        ]

    def validate(self, attrs):
        password = attrs.get("password", "")
        user_email = attrs.get("email", "")

        try:
            validate_email(user_email)
        except DjangoValidationError:
            raise serializers.ValidationError(
                "Enter a valid email address.",
            )

        if user_models.User.objects.filter(email=user_email).exists():
            raise serializers.ValidationError(
                "Email is already in use. Please use a different email.",
            )

        # Password Length Validation
        if len(password) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )

        # At least one uppercase letter
        if not re.search(r"[A-Z]", password):
            raise serializers.ValidationError(
                "Password must contain at least one uppercase letter."
            )

        # At least one lowercase letter
        if not re.search(r"[a-z]", password):
            raise serializers.ValidationError(
                "Password must contain at least one lowercase letter."
            )

        # At least one digit
        if not re.search(r"\d", password):
            raise serializers.ValidationError(
                "Password must contain at least one digit."
            )

        # At least one special character
        if not re.search(r"[@$!%*?&]", password):
            raise serializers.ValidationError(
                "Password must contain at least one special character (@, $, !, %, *, ?, &)."
            )

        # Password confirmation validation
        if password != attrs.get("confirm_password"):
            raise serializers.ValidationError("Passwords must match.")

        return attrs

    def validate_first_name(self, value):
        if not re.match(r"^[A-Za-z]+$", value):
            raise serializers.ValidationError(
                "First name must contain only alphabetic characters."
            )
        return value

    def validate_last_name(self, value):
        if not re.match(r"^[A-Za-z]+$", value):
            raise serializers.ValidationError(
                "Last name must contain only alphabetic characters."
            )
        return value

    def create(self, validated_data):
        validated_data.pop("confirm_password")

        user = user_models.User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            phone_number=validated_data.get("phone_number"),
            password=validated_data["password"],
            email_verified=False,
        )
        self.send_verification_email(user)
        return user

    def send_verification_email(self, user):
        verification_link = f"{settings.EMAIL_VERIFY_URL}{user.email_token}"
        subject = "Welcome"
        message = f"Hi {user.first_name}, thank you for registering. Verify your account by clicking the following link: {verification_link}"
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email]
        send_mail(subject, message, email_from, recipient_list)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        try:
            user = user_models.User.objects.get(email=email)
        except user_models.User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        if not user.is_active:
            raise serializers.ValidationError(
                "This account is inactive. Please contact support."
            )

        user = authenticate(username=user.email, password=password)

        if not user:
            raise serializers.ValidationError(
                "Invalid email or password. Please try again."
            )

        if not user.email_verified:
            raise serializers.ValidationError(
                "Email is not verified. Please verify your email to log in."
            )

        if not user.is_active:
            raise serializers.ValidationError(
                "This account is inactive. Please contact support."
            )

        user.last_login = timezone.now()
        user.save()

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token
        return {
            "refresh": str(refresh),
            "access": str(access_token),
            "user": {
                "id": user.id,
                "email": user.email,
                # "username":user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone_number": user.phone_number,
            },
        }


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):
        if not user_models.User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                {"success": False, "message": "User with this email does not exist."}
            )
        return email


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user_email = self.context.get("user")
        user = user_models.User.objects.filter(email=user_email).first()

        if not user:
            raise serializers.ValidationError(
                "User with this email does not exist.",
            )

        # if not user.last_login:
        #     raise serializers.ValidationError(
        #         "User account is not logged in yet.",
        #     )

        if user.has_usable_password():
            if not data.get("current_password"):
                raise serializers.ValidationError(
                    "Current password is required to change your password.",
                )

            if not user.check_password(data.get("current_password")):
                raise serializers.ValidationError(
                    "Current password is incorrect.",
                )
        else:
            if data.get("current_password"):
                raise serializers.ValidationError(
                    "Current password is not required as no password is set for your account.",
                )

        # Validate the new password strength.
        if not re.match(
            r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            data.get("new_password"),
        ):
            raise serializers.ValidationError(
                "Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
            )

        # Ensure the new password and confirm password match.
        if data["new_password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                "Passwords do not match.",
            )

        # Additional validation for the new password.
        self.validate_new_password(value=data.get("new_password"))

        return data

    def validate_new_password(self, value):
        user = self.context.get("user")
        # Ensure the new password is not the same as the current password.
        if user.check_password(value):
            raise serializers.ValidationError(
                "The new password cannot be the same as the current password.",
            )

        # Validate the password using Django's validate_password function.
        try:
            validate_password(value, user=user)
        except serializers.ValidationError as e:
            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": e.messages,
                }
            )

        return value


class SignoutSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        if not value:
            raise serializers.ValidationError(
                {"success": False, "message": "Refresh token is required."}
            )
        return value


class UserProfileSerializer(serializers.ModelSerializer):
    email = serializers.CharField(read_only=True, source="user.email")
    full_name = serializers.SerializerMethodField()
    phone_number = serializers.CharField(read_only=True, source="user.phone_number")

    class Meta:
        model = user_models.UserProfile
        fields = [
            "email",
            "full_name",
            "phone_number",
            "address",
            "profile_picture",
            "city",
            "state",
            "zipcode",
            "bio",
        ]

    def get_full_name(self, obj):
        first_name = obj.user.first_name or ""
        last_name = obj.user.last_name or ""
        return f"{first_name} {last_name}".strip()


class UserUpdateProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", required=False)
    first_name = serializers.CharField(source="user.first_name", required=False)
    last_name = serializers.CharField(source="user.last_name", required=False)
    email = serializers.CharField(source="user.email", required=False)
    phone_number = serializers.CharField(source="user.phone_number", required=False)

    class Meta:
        model = user_models.UserProfile
        fields = [
            "username",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "profile_picture",
            "city",
            "state",
            "zipcode",
            "bio",
            "profile_picture",
        ]

    def update(self, instance, validated_data):
        user_data = validated_data.pop("user", {})

        # Update UserProfile fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update related User fields
        user = instance.user
        for attr, value in user_data.items():
            setattr(user, attr, value)
        user.save()

        return instance


class CustomerOrderListSerializer(serializers.ModelSerializer):
    phone_number = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    order_total = serializers.FloatField(source="total_amount")

    class Meta:
        model = core_models.Payment
        fields = [
            "id",
            "full_name",
            "phone_number",
            "order_id",
            "made_on",
            "order_total",
        ]

    def get_full_name(self, obj):
        first_name = obj.orderproduct.Order.first_name or ""
        last_name = obj.orderproduct.Order.last_name or ""
        return f"{first_name} {last_name}".strip()

    def get_phone_number(self, obj):
        try:
            return obj.orderproduct.Order.phone_number
        except AttributeError:
            return None


class ProductSerializer(serializers.ModelSerializer):
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
            "user",
            "category",
        ]


class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = core_models.Order
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "state",
            "city",
            "zipcode",
        ]


class CustomerOrderProductDetailSerializer(serializers.ModelSerializer):
    product = serializers.SerializerMethodField()
    total_product_amount = serializers.FloatField(read_only=True)

    class Meta:
        model = core_models.OrderProduct
        fields = ["id", "product", "quantity", "total_product_amount"]

    def get_product(self, obj):
        return {
            "id": obj.product.id,
            "title": obj.product.title,
            "description": obj.product.description,
            "discounted_price": obj.product.discounted_price,
            "brand": obj.product.brand if obj.product.brand else None,
        }


class CustomerOrderDetailSerializer(serializers.ModelSerializer):
    orderproducts = serializers.SerializerMethodField()
    amount = serializers.SerializerMethodField()
    shipping_amount = serializers.SerializerMethodField()
    total_amount = serializers.SerializerMethodField()

    full_name = serializers.SerializerMethodField()
    address = serializers.SerializerMethodField()
    state = serializers.SerializerMethodField()
    city = serializers.SerializerMethodField()
    zipcode = serializers.SerializerMethodField()

    class Meta:
        model = core_models.Payment
        fields = [
            "id",
            "payment_type",
            "order_id",
            "made_on",
            "amount",
            "shipping_amount",
            "total_amount",
            "payment_status",
            "orderproducts",
            "full_name",
            "address",
            "state",
            "city",
            "zipcode",
        ]

    def get_orderproducts(self, obj):
        order = obj.orderproduct.Order
        order_products = core_models.OrderProduct.objects.filter(Order=order)
        return CustomerOrderProductDetailSerializer(order_products, many=True).data

    def get_amount(self, obj):
        order = obj.orderproduct.Order
        order_products = core_models.OrderProduct.objects.filter(Order=order)
        return sum([op.quantity * op.product.discounted_price for op in order_products])

    def get_shipping_amount(self, obj):
        return 70.0  # static value as required

    def get_total_amount(self, obj):
        return self.get_amount(obj) + self.get_shipping_amount(obj)

    def get_full_name(self, obj):
        first_name = obj.orderproduct.Order.first_name or ""
        last_name = obj.orderproduct.Order.last_name or ""
        return f"{first_name} {last_name}".strip()

    def get_address(self, obj):
        try:
            return obj.orderproduct.Order.address
        except AttributeError:
            return None

    def get_state(self, obj):
        try:
            return obj.orderproduct.Order.state
        except AttributeError:
            return None

    def get_city(self, obj):
        try:
            return obj.orderproduct.Order.city
        except AttributeError:
            return None

    def get_zipcode(self, obj):
        try:
            return obj.orderproduct.Order.zipcode
        except AttributeError:
            return None


class CategoryWithProductAndReviewSerializer(serializers.ModelSerializer):
    products = serializers.SerializerMethodField()

    class Meta:
        model = core_models.Category
        fields = ["id", "title", "category_image", "products"]

    def get_products(self, obj):
        products = obj.product_set.all()
        result = []
        for product in products:
            reviews = getattr(product, "reviews", [])
            result.append(
                {
                    "id": product.id,
                    "title": product.title,
                    "selling_price": product.selling_price,
                    # 'discounted_price': product.discounted_price,
                    # 'description': product.description,
                    "brand": product.brand,
                    "product_image": product.product_image.url
                    if product.product_image
                    else None,
                    "reviews": [
                        {
                            "id": review.id,
                            "name": review.user.first_name,
                            "subject": review.subject,
                            "review": review.review,
                            "rating": review.rating,
                            # 'created_at': review.created_at
                        }
                        for review in reviews
                    ],
                }
            )
        return result


class ProductFullSerializer(serializers.ModelSerializer):
    category_title = serializers.SerializerMethodField()
    # category_image = serializers.SerializerMethodField()
    average_review = serializers.SerializerMethodField()
    reviews = serializers.SerializerMethodField()
    product_image = serializers.ImageField(use_url=True)

    class Meta:
        model = core_models.Product
        fields = [
            "id",
            "title",
            "selling_price",
            # "discounted_price",
            # "description",
            "brand",
            "product_image",
            "category_title",
            # "category_image",
            "average_review",
            "reviews",
        ]

    def get_category_title(self, obj):
        return obj.category.title if obj.category else None

    # def get_category_image(self, obj):
    #     if obj.category and obj.category.category_image:
    #         request = self.context.get('request')
    #         return request.build_absolute_uri(obj.category.category_image.url) if request else obj.category.category_image.url
    #     return None

    def get_average_review(self, obj):
        return obj.averageReview()

    def get_reviews(self, obj):
        reviews = core_models.ReviewRating.objects.filter(product=obj, status=True)
        return [
            {
                "id": review.id,
                "user_id": review.user.id,
                "rating": review.rating,
                "review": review.review,
                "created_at": review.created_at,
            }
            for review in reviews
        ]


class ProductDetailSerializer(serializers.ModelSerializer):
    average_review = serializers.SerializerMethodField()

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
            "average_review",
        ]

    def get_average_review(self, obj):
        return obj.averageReview()


class AddToCartSerializer(serializers.ModelSerializer):
    product = serializers.PrimaryKeyRelatedField(
        queryset=core_models.Product.objects.all()
    )

    class Meta:
        model = core_models.Cart
        fields = ["product", "quantity"]


class CartItemSerializer(serializers.ModelSerializer):
    product_id = serializers.IntegerField(source="product.id")
    title = serializers.CharField(source="product.title")
    brand = serializers.CharField(source="product.brand")
    discounted_price = serializers.FloatField(source="product.discounted_price")
    total_price = serializers.SerializerMethodField()

    class Meta:
        model = core_models.Cart
        fields = [
            "product_id",
            "title",
            "brand",
            "quantity",
            "discounted_price",
            "total_price",
        ]

    def get_total_price(self, obj):
        return obj.quantity * obj.product.discounted_price


class OrderProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = core_models.OrderProduct
        fields = "__all__"


class CheckoutSerializer(serializers.ModelSerializer):
    products = OrderProductSerializer(
        source="orderproduct_set", many=True, read_only=True
    )

    class Meta:
        model = core_models.Order
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "phone_number",
            "address",
            "state",
            "city",
            "zipcode",
            "products",
        ]

    def create(self, validated_data):
        request = self.context.get("request")
        user = request.user
        cart_items = core_models.Cart.objects.filter(user=user)

        shipping_charge = 70.0
        total_amount = (
            cart_items.aggregate(
                total_amount=Sum(F("product__discounted_price") * F("quantity"))
            )["total_amount"]
            or 0
        )

        order = core_models.Order.objects.create(user=user, **validated_data)

        for item in cart_items:
            core_models.OrderProduct.objects.create(
                Order=order,
                product=item.product,
                quantity=item.quantity,
                amount=total_amount,
                total_amount=total_amount + shipping_charge,
            )

        order.total_amount = total_amount + shipping_charge
        order.save()

        cart_items.delete()

        return order


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = core_models.Payment
        fields = ["payment_type"]
