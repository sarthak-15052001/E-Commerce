import re
from rest_framework import serializers, status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from userauths.models import User
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth.password_validation import validate_password
from core.models import *
# from E_Commerce_Website import utils


'''
serializers.Serializer: The base class for DRF serializers that allows you to define custom fields 
and validation logic.
'''

#<------------UserAuth Serailizers Starts From Here-------------------------------->

#<-----------------------------User Serializers Starts From Here--------------------------------->
class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    username = serializers.CharField(max_length=100)
    password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        password = data.get("password")
        email = data.get("email")

        # Check if the email already exists
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                {"email": "Email is already in use."}
            )

        # Password validations
        if len(password) < 8:
            raise serializers.ValidationError(
                {"password": "Password must be at least 8 characters long."}
            )
        if not any(c.isupper() for c in password):
            raise serializers.ValidationError(
                {"password": "Password must contain at least one uppercase letter."}
            )
        if not any(c.islower() for c in password):
            raise serializers.ValidationError(
                {"password": "Password must contain at least one lowercase letter."}
            )
        if not any(c.isdigit() for c in password):
            raise serializers.ValidationError(
                {"password": "Password must contain at least one number."}
            )
        if not any(c in "!@#$%^&*()_+[]{}|;:,.<>?`~" for c in password):
            raise serializers.ValidationError(
                {"password": "Password must contain at least one symbol."}
            )
        if password != data.get("confirm_password"):
            raise serializers.ValidationError(
                {"confirm_password": "Passwords do not match."}
            )

        # Username validation
        if not re.match(r"^[a-zA-Z]+$", data.get("username", "")):
            raise serializers.ValidationError(
                {"username": "Username can only contain letters."}
            )

        return data  # Ensure validated data is returned

# Purpose: This defines a create method to handle the creation of a new user instance.

    def create(self, validated_data):
        # Remove confirm_password before creating the user
        validated_data.pop('confirm_password')        # Removes the confirm_password field from the validated_data dictionary. confirm_password is used to confirm the user's entered password (e.g., during registration), but it is not a part of the User model. It doesn't need to be saved to the database, so it's removed before further processing.
        password = validated_data.pop('password')     # Extracts the password field from the validated_data dictionary and assigns it to the variable password.
        
        # Create the user instance
        user = User(                                  # Creates a new User instance without saving it to the database yet.
            username=validated_data['username'],       # Sets the username of the User instance using the value from validated_data.The username is a required field for most user models in Django and must be assigned
            email=validated_data['email'],
        )
        user.set_password(password)  # Hash the password
        user.save()

        # Optionally, send a verification email
        self.send_verification_email(user)
        return user
    

    def send_verification_email(self, user):
        verification_link = f"{settings.EMAIL_VERIFY_URL}/{user.email_token}"
        subject = "Welcome to Shopping X Website"
        message = f"Hi {user.username}, thank you for registering. Verify your account by clicking the following link: {verification_link}"
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [user.email]
        send_mail(subject, message, email_from, recipient_list)



#<-------------------------CustomToken Serializer Starts From Here------------------------------>
class CustomTokenObtainPairSerializer(serializers.Serializer):
    email = serializers.EmailField()                         #  A field for accepting the user's email. The EmailField ensures the input is a valid email format.
    password = serializers.CharField(write_only=True)        # A field for accepting the user's password. 

    def validate(self, attrs):                      # The validate method is called automatically during validation.
        email = attrs.get("email")                  # attrs.get("email") and attrs.get("password") retrieve the values of the fields provided in the request payload.
        password = attrs.get("password")
        
        # Authenticate the user
        user = authenticate(username=email, password=password)  # authenticate: A Django method that checks if the provided email and password correspond to a valid user. If the credentials are invalid, user will be None.
        
        if user is None:                                       # If the authenticate method fails, a ValidationError is raised, stopping further validation and returning an error message.
            raise serializers.ValidationError({"message": "User does not exist or password is incorrect."})
        
        if not user.is_active:
            raise serializers.ValidationError({"message": "User account is not active."})
        
        # Check if the email is verified
        if not user.email_verified:   # If the user's email is not verified (assuming email_verified is a custom field on the User model), an error is raised asking the user to verify their email.
            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": "Email is not verified. Please verify your email to log in.",
                }
            )
        
        # Check if the password matches
        if not user.check_password(password):                # If the password provided is incorrect (even though authenticate already checks this), a specific error message is raised.
            raise serializers.ValidationError(
                {
                    "message": "Password is incorrect, please verify.",
                }
            )
        
        # Update the last login
        user.last_login = timezone.now()                 # Updates the last_login field of the user to the current timestamp using Django's timezone.now().
        user.save() 

        # Generate tokens
        refresh = RefreshToken.for_user(user)            # Generates a pair of JWT tokens (refresh and access) for the authenticated user.
        
        # Serialize user details (use UserSerializer if you have one)
        user_data = {                           # A dictionary containing user details
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }

        return {
            "success": True,
            "message": "Logged in successfully.",
            "data": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": user_data,
            }
        }

#<-------------------------Change password Serializer Starts From Here--------------------------->
class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context.get("user")           # Retrieves the currently logged-in user from the serializer's context.

        if not user.check_password(data.get("current_password")):   # Verifies if the provided current_password matches the user's actual password.
            raise serializers.ValidationError(                       # If the password is incorrect, a ValidationError is raised with an error message.
                {
                    "success": False,
                    "message": "Current password is incorrect.",
                }
            )
        
        # Validate password complexity
        if not re.match(
            r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            data.get("password"),
        ):
            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": "Password must meet the required complexity.",
                }
            )

        # Ensure the new password and confirm password match
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError(
                {"success": False, "message": "Passwords do not match."}
            )

        # Additional validation for new password
        self.validate_new_password(value=data.get("password"))   # Calls the custom validate_new_password method to perform additional checks on the new password.
        return data
    

    def validate_new_password(self, value):
        user = self.context.get("user")
        if user.password == value:          # Checks if the new password is the same as the current password. If true, a ValidationError is raised.

            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": "The new password cannot be the same as the current password.",
                }
            )
        try:
            validate_password(value, user=user)          # A Django utility that applies built-in password validators (e.g., minimum length, dictionary checks).
        except serializers.ValidationError as e:
            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": e.messages,
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return value
    

#<-----------------------Forget Password Serializer Starts From Here--------------------------->
class ForgetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, email):            # A custom validation method for the email field.
        if not User.objects.filter(email=email).exists(): # This queries the User model to check if there is any user with the given email address. Filters the User model objects to find entries where the email field matches the provided value. Returns True if the query finds at least one matching record; otherwise, it returns False.
            raise serializers.ValidationError(            # If no user is found, the condition evaluates to True.   
                {
                    "success": False,
                    "message": "User with this email does not exist.",
                }
            )
        return email                                     # Always return the validated email
    

#<----------------------Reset Password Serializer Starts From Here--------------------------->
class ResetPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if not re.match(
            r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            data.get("password"),
        ):
            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": "Password must meet the required complexity.",
                }
            )
        if data["password"] != data["confirm_password"]:            # Ensures the password and confirm_password fields are same.
            raise serializers.ValidationError(
                {"success": False, "message": "Passwords do not match."}
            )
        self.validate_new_password(value=data.get("password"))       # Calls a custom method (validate_new_password) for additional validation logic
        return data
    

    def validated_new_password(self, value):
        user = self.context.get("user")       # Ensures the new password is different from the user’s current password.
        if user.password == value:            # If the new password matches the current password, a ValidationError is raised.
            raise serializers.ValidationError(
                {
                    "success": False,
                    "message": "The new password cannot be the same as the current password.",
                }
            )
        try:
            validate_password(value, user=user)           # A Django utility that checks the password against built-in validators (e.g., common password checks, minimum length).
        except serializers.ValidationError as e:
            raise serializers.ValidationError(             # If the validation fails, the error messages are returned in a ValidationError.
                {"sucess": False, "message": e.messages},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return value
    


#<-------------------------Signout Serializer Starts From Here---------------------------->
class SignoutSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

    def validate_refresh_token(self, value):
        if not value:                          # Checks if the provided value (i.e., the refresh token) is empty, None, or invalid. This is crucial because an empty or missing refresh token would indicate a problem in the sign-out process.
            raise serializers.ValidationError(
                {"success": False, "message": "Refresh token is required."}
            )
        return value
    

#<-----------------------------Admin API Starts From Here------------------------------------->

#<-----------------------------Admin Profile Serializer Starts From Here----------------------->
'''
1) source='user.username'
What is it?
source is used to map a serializer field to a specific attribute in the model or nested model.
In this case, source='user.username' tells the serializer to get or set the value from the username 
attribute of the user model, which is likely related to the UserProfile model.

Why use it?
To access fields from a related model (User) while working with another model (e.g., UserProfile).
Without source, the serializer would look for username directly in the UserProfile instance, which 
might not exist.

Example
If your UserProfile model has a foreign key to the User model (e.g., user = models.OneToOneField(User)), 
this allows you to access username via user.username.
username = serializers.CharField(source='user.username', required=False)
Maps the username field in the serializer to the user.username attribute in the database.

2) required=False
What is it?
required determines whether a field must be included in the input data.
Why use it?
required=False makes the field optional. The serializer will not raise a validation error if the 
field is missing in the input.
This is useful for partial updates or optional fields where users are not required to provide certain 
data.

3) allow_blank=True
What is it?
allow_blank is specific to string fields and determines whether empty strings ("") are valid input.

Why use it?
allow_blank=True allows users to provide an empty string for a field (e.g., leaving the first_name or 
bio blank).
Without this, an empty string would raise a validation error.

for eg:- A user can submit:-
{
    "first_name": ""
}

4. allow_null=True
What is it?
allow_null is specific to fields where None (null in JSON) is allowed as a value.
Why use it?
allow_null=True allows the field to accept null as a valid value in the input.
This is especially important for fields that map to database columns that can store NULL values 
(e.g., integer or date fields).

for eg:- A user can submit:-
{
    "phone_number": null
}
This will set the phone_number field to None in the database.
'''


class AdminProfileSerializer(serializers.Serializer):
    username = serializers.CharField(source='user.username', required=False)
    email = serializers.EmailField(source='user.email', required=False)
    first_name = serializers.CharField(source='user.first_name', required=False, allow_blank=True)  
    last_name = serializers.CharField(source='user.last_name', required=False, allow_blank=True)
    phone_number = serializers.IntegerField(source='user.phone_number', required=False, allow_null=True)
    address = serializers.CharField(required=False, allow_blank=True)
    profile_picture = serializers.ImageField(required=False)
    city = serializers.CharField(required=False, allow_blank=True)
    state = serializers.CharField(required=False)
    zipcode = serializers.IntegerField(required=False, allow_null=True)
    bio = serializers.CharField(required=False, allow_blank=True)


    def update(self, instance, validated_data):
        # Update related User Fields
        user_data = validated_data.pop('user', {})    # Extracts the user-related data (e.g., username, email) from validated_data. Removes this data from validated_data to avoid processing it as part of the UserProfile.
        for attr, value in user_data.items():         # Loops through each key-value pair in user_data.
            setattr(instance.user, attr, value)       # Dynamically sets each user attribute (e.g., user.username, user.email) to the new value.
        instance.user.save()                          # Saves the updated User model to the database
 
        # Handle profile picture explicitly
        profile_picture = validated_data.pop('profile_picture', None)    # Extracts the profile_picture field from validated_data, if present. Removes it to prevent duplication during the next step
        if profile_picture:                               # Checks if a new profile picture was provided.
            instance.profile_picture = profile_picture     # Updates the profile_picture field of the UserProfile instance
 
        # Update other UserProfile Fields
        for attr, value in validated_data.items():         # Loops through the remaining fields in validated_data (fields specific to the UserProfile).
            setattr(instance, attr, value)                 # Dynamically updates each field of the UserProfile instance.

        instance.save()                                    # Saves the updated UserProfile instance to the database.
        return instance
    

# With Serializer------------------->>>>>>>>>>


#<--------------------------Admin Dashboard Serializer Starts From Here------------------------>
class AdminDashboardSerializer(serializers.Serializer):
    total_category = serializers.IntegerField()
    total_products = serializers.IntegerField()
    total_customers = serializers.IntegerField()
    total_orders = serializers.IntegerField()



#<--------------------------Admin Customer Serializer Starts From Here------------------------>
class AdminCustomerSerializer(serializers.Serializer):
    id = serializers.IntegerField(required=False)               # Include the user ID
    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    phone_number = serializers.IntegerField(required=False, allow_null=True)
    address = serializers.CharField(source='userprofile.address', required=False, allow_blank=True)  # Assuming address is part of UserProfile
    profile_picture = serializers.ImageField(source='userprofile.profile_picture', required=False)  # Assuming profile_picture is part of UserProfile
    city = serializers.CharField(source='userprofile.city', required=False, allow_blank=True)  # Assuming city is part of UserProfile
    state = serializers.CharField(source='userprofile.state', required=False)  # Assuming state is part of UserProfile
    zipcode = serializers.CharField(source='userprofile.zipcode', required=False, allow_null=True)  # Assuming zipcode is part of UserProfile
    bio = serializers.CharField(source='userprofile.bio', required=False, allow_blank=True)  # Assuming bio is part of UserProfile
    


#<-----------------------------Admin Order Serializer Starts From Here------------------------>
class AdminOrderSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.IntegerField()
    total_amount = serializers.FloatField(required=False)   # Derived from Payment
    made_on = serializers.DateTimeField(required=False)     # Derived from Payment
    order_id = serializers.IntegerField(required=False)     # Derived from Payment
    # products = serializers.ListField(child=serializers.DictField(), required=False)     

    def to_representation(self, instance):   # A method that overrides the default data representation logic. Converts the Order model instance into a customized dictionary format.
        """
        Customize the representation to include payment details.
        """
        # Fetch all related `OrderProduct` and corresponding `Payment` records
        order_products = OrderProduct.objects.filter(Order=instance)  # Retrieves all OrderProduct records associated with the Order instance.
        payments = Payment.objects.filter(orderproduct__Order=instance)  # Retrieves all Payment records linked to the current order.  Assumes a relationship like Payment -> OrderProduct -> Order.
        print('===========payments: ', payments)

        # Calculate the total amount from related payments
        total_amount = sum(payment.total_amount for payment in payments)        # Sums the total_amount attribute from all related Payment records.
        made_on = payments.first().made_on if payments.exists() else None       # Uses the made_on attribute of the first payment if payments exist; otherwise, it's None.
        order_id = payments.first().order_id if payments.exists() else None     # Get order_id from the first payment

        # Prepare the product details
        products = [                                       # We can also add this product in this api
            {
                "product": order_product.product.title,
                "quantity": order_product.quantity,
                "price": order_product.price,              
                "amount": order_product.amount,
            } 
            for order_product in order_products            # To access each OrderProduct record in the queryset.
        ]


        return {
            "id": instance.id,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "phone_number": instance.phone_number,
            "total_amount": total_amount,
            "made_on": made_on,
            "order_id": order_id,
            # "products": products,
        }
    


'''
1) Why instance.<field> is Used?
What instance Represents

The instance refers to the specific object or record being serialized. It is passed to the 
serializer (or accessed internally) and contains all the fields and data for that object.

The instance represents the object passed to the serializer.
The serializer uses instance.<field> to fetch and include data from the object's attributes.

2) Accessing Data from the Object

instance.<field> is used to access the values of specific attributes (fields) of the object.


3) What Does Order=instance Mean?
Order:

It refers to the foreign key or field in the OrderProduct or Payment model that relates to the 
Order model.
This field establishes a relationship between an OrderProduct or Payment instance and a 
specific Order.

instance:

It is the current Order object for which the API is generating a response.
This instance is passed to the serializer as part of the context or directly when serializing.

Order=instance:

This filter retrieves only the OrderProduct or Payment records that are related to the specific 
Order instance.

Filter Related Data:

OrderProduct or Payment models may contain records for multiple orders.
By using Order=instance, you ensure that only the records related to the current Order instance are 
fetched.

Example Use Case
Database Schema
Order model:
Represents customer orders.
OrderProduct model:
Has a foreign key Order pointing to the Order model.
Represents individual products in an order.
Payment model:
Has a foreign key OrderProduct, which in turn relates to the Order model indirectly via Order.

Sample Data
Order Table:

ID	Customer Name	Date
1	John Doe	2024-12-01
2	Jane Smith	2024-12-02
OrderProduct Table:

ID	Product Name	Quantity	Order (FK)
1	Laptop	1	1
2	Mouse	2	1
3	Keyboard	1	2
Code Execution
If instance is the Order with ID 1, the filter Order=instance ensures only OrderProduct rows with 
Order=1 are fetched:

result:-
order_products = [
    {"product": "Laptop", "quantity": 1},
    {"product": "Mouse", "quantity": 2},
]

4) Indirect Filtering Example
payments = Payment.objects.filter(orderproduct__Order=instance)

is an indirect query using the reverse relationship. Here's how it works:

orderproduct__Order:
The double underscore (__) is used for querying across model relationships.
orderproduct__Order traverses from Payment → OrderProduct → Order.
Order=instance:
Filters only those payments that are related to the current order via its OrderProduct records.
'''

#<---------------------------Admin Order Detail Serializer Starts From Here--------------------->
class AdminOrderDetailSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    first_name = serializers.CharField()
    last_name = serializers.CharField()
    phone_number = serializers.IntegerField()
    sub_total = serializers.IntegerField()
    total_amount = serializers.FloatField(required=False)   # Derived from Payment
    made_on = serializers.DateTimeField(required=False)     # Derived from Payment
    order_id = serializers.IntegerField(required=False)     # Derived from Payment
    payment_type = serializers.CharField(required=False)    # Derived from Payment
    payment_status = serializers.CharField(required=False)  # Derived from Payment
    products = serializers.ListField(child=serializers.DictField(), required=False)


    def to_representation(self, instance):
        """
        Customize the representation to include payment details.
        """
        # Fetch all related `OrderProduct` and corresponding `Payment` records
        order_products = OrderProduct.objects.filter(Order=instance)
        payments = Payment.objects.filter(orderproduct__Order=instance)
        print('===========payments: ', payments)


        # Taken fields from related payments
        total_amount = sum(payment.total_amount for payment in payments)
        made_on = payments.first().made_on if payments.exists() else None
        order_id = payments.first().order_id if payments.exists() else None   # Get order_id from the first payment
        payment_type = payments.first().payment_type if payments.exists() else None
        paymnet_status = payments.first().payment_status if payments.exists() else None



        # Calculate sub_total as the sum of all product amounts (amount * quantity)
        sub_total = sum(order_product.total_product_amount for order_product in order_products)


        # Prepare the product details
        products = [
            {
                "product": order_product.product.title,
                "brand": order_product.product.brand,
                "quantity": order_product.quantity,
                "price": order_product.total_product_amount,
            }
            for order_product in order_products
        ]


        return {
            "id": instance.id,
            "first_name": instance.first_name,
            "last_name": instance.last_name,
            "phone_number": instance.phone_number,
            "address": instance.address,
            "state": instance.state,
            "city": instance.city,
            "zip_code": instance.zipcode,
            "order_id": order_id,
            "payment_type": payment_type,
            "made_on": made_on,
            "paymnet_status": paymnet_status,
            "sub_total": sub_total,
            "shipping_charges": 70.0,
            "total_amount": total_amount,
            "products": products,
        }
    

'''
Explanation of Components
products:

This is the name of the field being defined in the serializer.
It represents a list of items, where each item is expected to be a dictionary.
serializers.ListField:

A field in DRF used to represent a list of values.
It ensures that the incoming data for this field is a list.
child=serializers.DictField():

Specifies the type of each item within the list.
In this case, each item in the list must be a dictionary (DictField).
A DictField represents a JSON-like object with key-value pairs, where the keys are strings, and the
values can be of any type.
required=False:

Makes the products field optional.
If this field is not provided in the request data, it will not raise a validation error.
Why Use ListField with DictField?
This combination is used when you expect a list of dictionaries as input data. For example, this 
could be used to represent a collection of products in an order.


'''

#<---------------------------Admin Category Serializer Starts From Here------------------------->
class AdminCategorySerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(required=True, max_length=255)
    category_image = serializers.ImageField(required=True)


    def create(self, validated_data):
        """
        Create a new Category instance with validated data.
        """
        return Category.objects.create(**validated_data)             # The **validated_data unpacks the dictionary into keyword arguments. For example, if validated_data = {'title': 'Electronics', 'category_image': <image>}
    

    def update(self, instance, validated_data):
        """
        Update an existing Category instance with validated data.
        """
        instance.title = validated_data.get('title', instance.title)
        instance.category_image = validated_data.get('category_image', instance.category_image)
        instance.save()
        return instance
    

'''
instance.title (before the equals sign):

Refers to the existing value of the title field in the instance.
This is the value being updated.

validated_data.get('title', instance.title) (inside the parentheses):

Fetches the value of the title field from validated_data if it exists.
If validated_data does not contain a value for title (e.g., the user didn't provide it in the 
API request), it defaults to the current value of instance.title.

Why Use instance.title in Both Places?
This approach ensures partial updates while maintaining existing data.

Default to the Existing Value:

If the title key is not present in the input data (validated_data), the current value of 
instance.title is retained.
Without this fallback, the title field could be overwritten as None or invalidated.
Support for Updating Individual Fields:

The serializer might receive input where only some fields need to be updated (not all).
For example:
json
Copy code
{
  "category_image": "new_image.png"
}
In this case, you want to update only the category_image and leave title unchanged.
How It Works in Steps
Input Data Validation:

Assume validated_data = {"category_image": "new_image.png"}.
The title key is missing in validated_data.
Use .get() with a Fallback:

validated_data.get('title', instance.title):
Checks if title exists in validated_data.
If not, it uses the current value of instance.title.
Assign the Value:

The title field of the instance is updated only if a new value is provided.
Otherwise, it retains its original value.
Example
Initial Category Instance:
python
Copy code
instance = Category(id=1, title="Electronics", category_image="old_image.png")
Input Data for Update:
json
Copy code
{
  "category_image": "new_image.png"
}
Execution of the Code:
python
Copy code
# 'title' is not provided in the validated data, so the default (instance.title) is used.
instance.title = validated_data.get('title', instance.title)  
# Result: instance.title = "Electronics"

# 'category_image' is updated with the new value.
instance.category_image = validated_data.get('category_image', instance.category_image)
# Result: instance.category_image = "new_image.png"

instance.save()
Final Updated Instance:
python
Copy code
instance = Category(id=1, title="Electronics", category_image="new_image.png")


'''
    

    # def validate_category_image(self, value):
    #     """
    #     Additional validation for the uploaded image if needed.
    #     """
    #     if not value.content_type.startswith('image/'):
    #         raise serializers.ValidationError("Only image files are allowed.")
    #     return value
    

    # def to_representation(self, instance):
    #     """
    #     Customize the serialization output.
    #     Return the flat structure: id, title, category_image.
    #     """
    #     # Create a dictionary with the desired structure
    #     representation = {
    #         'id': instance.id,
    #         'title': instance.title,
    #         'category_image': instance.category_image.url if instance.category_image else None
    #     }
    #     return representation





#<--------------------------------Admin Product Serializer Starts From Here------------------------>
class AdminProductSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    title = serializers.CharField(max_length=100)
    selling_price = serializers.FloatField()
    discounted_price = serializers.FloatField()
    description = serializers.CharField()
    brand = serializers.CharField(max_length=100)
    product_image = serializers.ImageField()
    user = serializers.CharField()
    category = serializers.CharField()


    def create(self, validated_data):

        # Fetch user and category instances
        user = User.objects.get(username=validated_data['user'])
        category = Category.objects.get(title=validated_data['category'])


        # Create Product
        return Product.objects.create(
            title=validated_data['title'],
            selling_price=validated_data['selling_price'],
            discounted_price=validated_data['discounted_price'],
            description=validated_data['description'],
            brand=validated_data['brand'],
            product_image=validated_data['product_image'],
            user=user,
            category=category
        )
    

    def update(self, instance, validated_data):
        instance.title = validated_data.get('title', instance.title)
        instance.selling_price = validated_data.get('selling_price', instance.selling_price)
        instance.discounted_price = validated_data.get('discounted_price', instance.discounted_price)
        instance.description = validated_data.get('description', instance.description)
        instance.brand = validated_data.get('brand', instance.brand)
        instance.product_image = validated_data.get('product_image', instance.product_image)
        
        # Update user and category if provided
        if 'user' in validated_data:
            instance.user = User.objects.get(username=validated_data['user'])
        if 'category' in validated_data:
            instance.category = Category.objects.get(title=validated_data['category'])
        
        instance.save()
        return instance


