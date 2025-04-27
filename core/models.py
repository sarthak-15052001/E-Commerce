import random
from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from userauths.models import *
from django.urls import reverse

# Create your models here.


class Category(models.Model):
    title = models.CharField(max_length=100)
    category_image = models.ImageField(upload_to="category")

    def __str__(self):
        return str(self.title)
    
    class Meta:
        verbose_name_plural = "Categories"


    def get_url(self):
        return reverse("core:products_by_category", kwargs={'category_title': self.title})
         

class Product(models.Model):
    title = models.CharField(max_length=100)
    selling_price = models.FloatField()
    discounted_price = models.FloatField()
    description = models.TextField()
    brand = models.CharField(max_length=100)
    product_image = models.ImageField(upload_to="product")
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)

    class Meta:
        verbose_name_plural = "Products"



class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(default=1)

    class Meta:
        verbose_name_plural = "Cart"



STATE_CHOICES = (
    ('Andaman & Nicobar Islands', 'Andaman & Nicobar Islands'),
    ('Andhra Pradesh', 'Andhra Pradesh'),
    ('Arunachal Pradesh', 'Arunachal Pradesh'),
    ('Assam', 'Assam'),
    ('Bihar', 'Bihar'),
    ('Chandigarh', 'Chandigarh'),
    ('Chhattisgarh', 'Chhattisgarh'),
    ('Dadra & Nagar Haveli', 'Dadra & Nagar Haveli'),
    ('Daman & Diu', 'Daman & Diu'),
    ('Delhi', 'Delhi'),
    ('Goa', 'Goa'),
    ('Gujarat', 'Gujarat'),
    ('Haryana', 'Haryana'),
    ('Himachal Pradesh', 'Himachal Pradesh'),
    ('Jammu & Kashmir', 'Jammu & Kashmir'),
    ('Jharkhand', 'Jharkhand'),
    ('Karnataka', 'karnataka'),
    ('Kerala', 'Kerala'),
    ('Lakshadweep', 'Lakshadweep'),
    ('Madhya Pradesh', 'Madhya Pradesh'),
    ('Maharashtra', 'Maharashtra'),
    ('Manipur', 'Manipur'),
    ('Meghalaya', 'Meghalaya'),
    ('Mizoram', 'Mizoram'),
    ('Nagaland', 'Nagaland'),
    ('Odisha', 'Odisha'),
    ('Puducherry', 'puducherry'),
    ('Punjab', 'Punjab'),
    ('Rajasthan', 'Rajasthan'),
    ('Sikkim', 'Sikkim'),
    ('Tamil Nadu', 'Tamil Nadu'),
    ('Telangana', 'Telangana'),
    ('Tripura', 'Tripura'),
    ('Uttarakhand', 'Uttarakhand'),
    ('Uttar Pradesh', 'Uttar Pradesh'),
    ('West Bengal', 'West Bengal'),
)




class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    cart = models.ForeignKey(Cart, on_delete=models.CASCADE, blank=True,null=True)
    first_name = models.CharField(max_length=100,blank=True,null=True)
    last_name = models.CharField(max_length=100,blank=True,null=True)
    email = models.EmailField(max_length=150,blank=True,null=True)
    phone_number = models.IntegerField(blank=True,null=True)
    address = models.CharField(max_length=200, blank=True,null=True)
    state = models.CharField(choices=STATE_CHOICES, max_length=50)
    city = models.CharField(max_length=50)
    zipcode = models.IntegerField()

    class Meta:
        verbose_name_plural = "Orders"

    def __str__(self): 
        return str(self.id)


class OrderProduct(models.Model):
    Order = models.ForeignKey(Order, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    quantity = models.IntegerField(blank=True, null=True)
    price = models.IntegerField(blank=True, null=True)
    amount = models.FloatField(blank=True,null=True)
    total_amount = models.FloatField(blank=True,null=True)


    @property
    def total_product_amount(self):
        return self.quantity * self.product.discounted_price


    class Meta:
        verbose_name_plural = "Order Products"



PAYMENT_TYPE = (
    ('Cash', 'Cash'),
    ('Card', 'Card'),
    ('Paypal', 'Paypal')
)


PAYMENT_STATUS = (
    ('Paid', 'Paid'),
    ('Not Paid', 'Not Paid')
)

class Payment(models.Model):
    payment_type = models.CharField(max_length=30, choices=PAYMENT_TYPE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    orderproduct = models.ForeignKey(OrderProduct, on_delete=models.CASCADE)
    order_id = models.IntegerField(unique=True, null=True, blank=None)
    made_on = models.DateTimeField(auto_now_add=True)
    total_amount = models.FloatField()
    payment_status = models.CharField(max_length=30, choices=PAYMENT_STATUS, default="Not Paid")


    class Meta:
        verbose_name_plural = "Payments"


    def save(self, *args, **kwargs):
        if not self.order_id:
            self.order_id = random.randint(1000, 9999)
        super().save(*args, **kwargs)