from html import escape
from werkzeug.security import generate_password_hash, check_password_hash
import random

class Book:
    def __init__(self, title, category, price, image):
        self.title = title
        self.category = category
        self.price = price
        self.image = image
# In future Id like to add an Author class and link books to authors 

class CartItem:
    def __init__(self, book, quantity=1):
        self.book = book
        self.quantity = quantity
    
    def get_total_price(self):
        return self.book.price * self.quantity


class Cart:
    """
    A shopping cart class that holds book items and their quantities.

    The Cart uses a dictionary with book titles as keys for efficient lookups,
    allowing operations like adding, removing, and updating book quantities.

    Attributes:
        items (dict): Dictionary storing CartItem objects with book titles as keys.

    Methods:
        add_book(book, quantity=1): Add a book to the cart with specified quantity.
        remove_book(book_title): Remove a book from the cart by title.
        update_quantity(book_title, quantity): Update quantity of a book in the cart.
        get_total_price(): Calculate total price of all items in the cart.
        get_total_items(): Get the total count of all books in the cart.
        clear(): Remove all items from the cart.
        get_items(): Return a list of all CartItem objects in the cart.
        is_empty(): Check if the cart has no items.
    """
    def __init__(self):
        self.items = {}  # Using dict with book title as key for easy lookup

    def add_book(self, book, quantity=1):
        if book.title in self.items:
            self.items[book.title].quantity += quantity
        else:
            self.items[book.title] = CartItem(book, quantity)

    def remove_book(self, book_title):
        if book_title in self.items:
            del self.items[book_title]

# Fixes two issues, one where the cart didnt update properly if 0 quantity was set
# and the other where negative quantities could be set and completely break the cart
    def update_quantity(self, book_title, quantity):
        if book_title in self.items:
            # Only update if quantity is non-negative
            if quantity >= 0:
                self.items[book_title].quantity = quantity

# Fixes efficiency issue where total price was calculated using unnecessary loops
    def get_total_price(self):
        return sum(item.get_total_price() for item in self.items.values())

    def get_total_items(self):
        return sum(item.quantity for item in self.items.values())

    def clear(self):
        self.items = {}

    def get_items(self):
        return list(self.items.values())

    def is_empty(self):
        return len(self.items) == 0

# Adds HTML escaping for user inputs to prevent XSS
class User:
    """User account management class"""
    def __init__(self, email, password, name="", address="", is_hashed=False):
        self.email = escape(email)
        # Hash the password if it's not already hashed
        if is_hashed:
            self.password_hash = escape(password)
        else:
            self.password_hash = generate_password_hash(password)
        self.name = escape(name)
        self.address = escape(address)
        self.orders = []
        self.temp_data = []
        self.cache = {}
# Adds password hashing so we stop storing passwords in plain text
# This was a nightmare to figure out and in hindsight I probably should have just documented
# that passwords are stored in plain text for the sake of simplicity
# but I wanted to see if I could figure it out.
# There was alot of googling and breaking all the unit tests involved
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        """Set a new password (hashes it automatically)"""
        self.password_hash = generate_password_hash(password)
    
    @property
    def password(self):
        """Getter for backwards compatibility - raises error if accessed directly"""
        raise AttributeError('password is not a readable attribute. Use check_password() instead.')
    
    @password.setter
    def password(self, password):
        """Setter for backwards compatibility - hashes the password"""
        self.set_password(password)
    
    def add_order(self, order):
        self.orders.append(order)
        self.orders.sort(key=lambda x: x.order_date)
    
    def get_order_history(self):
        return [order for order in self.orders]


class Order:
    """Order management class"""
    def __init__(self, order_id, user_email, items, shipping_info, payment_info, total_amount):
        import datetime
        self.order_id = order_id
        self.user_email = user_email
        self.items = items.copy()  # Copy of cart items
        self.shipping_info = shipping_info
        self.payment_info = payment_info
        self.total_amount = total_amount
        self.order_date = datetime.datetime.now()
        self.status = "Confirmed"
    
    def to_dict(self):
        return {
            'order_id': self.order_id,
            'user_email': self.user_email,
            'items': [{'title': item.book.title, 'quantity': item.quantity, 'price': item.book.price} for item in self.items],
            'shipping_info': self.shipping_info,
            'total_amount': self.total_amount,
            'order_date': self.order_date.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status
        }


class PaymentGateway:
    """Mock payment gateway for processing payments"""
    
    @staticmethod
    def process_payment(payment_info):
        """Mock payment processing - returns success/failure with mock logic"""
        card_number = payment_info.get('card_number', '')
        
        # Mock logic: cards ending in '1111' fail, others succeed
        if card_number.endswith('1111'):
            return {
                'success': False,
                'message': 'Payment failed: Invalid card number',
                'transaction_id': None
            }
        
# Removed some random imports that were sitting here unused (Random was used so moved it to the top)
# Removed a time.sleep that was existing for no reason
        
        transaction_id = f"TXN{random.randint(100000, 999999)}"
        
        if payment_info.get('payment_method') == 'paypal':
            pass
        
        return {
            'success': True,
            'message': 'Payment processed successfully',
            'transaction_id': transaction_id
        }


class EmailService:
    """Mock email service for sending order confirmations"""
# I encountered an Dict attribute error when trying to test this
# so had to change how the order object was accessed (changed from order.order_id to order['order_id'] for example)
    @staticmethod
    def send_order_confirmation(user_email, order):
        """Mock email sending - just prints to console in this implementation"""
        print(f"\n=== EMAIL SENT ===")
        print(f"To: {user_email}")
        print(f"Subject: Order Confirmation - Order #{order['order_id']}")
        print(f"Order Date: {order['order_date']}")
        print(f"Total Amount: ${order['total_amount']:.2f}")
        print(f"Items:")
        for item in order['items']:
            print(f"  - {item['title']} x{item['quantity']} @ ${item['price']:.2f}")
        print(f"Shipping Address: {order['shipping_info'].get('address', 'N/A')}")
        print(f"==================\n")
        
        return True
