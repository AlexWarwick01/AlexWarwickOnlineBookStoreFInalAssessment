from locust import HttpUser, task, between
import random

class BookStoreUser(HttpUser):
    host = "http://localhost:5000"
    wait_time = between(1, 5)
    
    def on_start(self):
        """Setup before tests - login and add items to cart"""
        # Login with demo account
        response = self.client.post("/login", data={
            "email": "demo@bookstore.com",
            "password": "demo123"
        }, allow_redirects=True)
        
        if "Logged in successfully" not in response.text:
            print("Login failed!")
            return
            
        # Add multiple items to cart to ensure it's not empty
        for _ in range(2):
            self.client.post("/add-to-cart", data={
                "title": "The Great Gatsby",
                "quantity": "1"
            }, allow_redirects=True)
            
        # Verify cart has items
        cart_response = self.client.get("/cart")
        if "Your cart is empty" in cart_response.text:
            print("Failed to add items to cart!")

        self.order_id = None
# This took literally 3 hours to create and debug and Im sad now.
    @task(1)
    def process_checkout(self):
        """Test the checkout process"""
        # First check if we're logged in and cart has items
        cart_check = self.client.get("/cart")
        if "Your cart is empty" in cart_check.text:
            self.client.post("/add-to-cart", data={
                "title": "The Great Gatsby",
                "quantity": "1"
            }, allow_redirects=True)
            print("Added items to cart before checkout")

        # Updated checkout data to match Order class structure
        checkout_data = {
            # Order and shipping details
            "order_id": str(random.randint(1000, 9999)),  # Generate random order ID
            "user_email": "demo@bookstore.com",  # Use logged in user's email
            "shipping_name": "Test User",
            "shipping_address": "123 Test Street",
            "shipping_city": "Test City",
            "shipping_state": "TS",
            "shipping_zip": "12345",
            # Payment details
            "card_type": "credit_card",
            "card_number": "4111111111111112",
            "card_expiry": "12/25",
            "card_cvv": "123"
        }

        try:
            # Make the checkout request
            with self.client.post(
                "/process-checkout", 
                data=checkout_data,
                catch_response=True,
                allow_redirects=False  # Changed to catch redirect
            ) as response:
                print(f"\nCheckout attempt with data: {checkout_data}")
                print(f"Response status: {response.status_code}")
                
                if response.status_code == 302:
                    # Success case - redirect to order confirmation
                    redirect_url = response.headers.get('Location', '')
                    print(f"Redirect URL: {redirect_url}")
                    if 'order-confirmation' in redirect_url:
                        response.success()
                        return
                
                elif response.status_code == 500:
                    # Error case - server error
                    print(f"Server error response: {response.text[:200]}")
                    response.failure(f"Server error during checkout: {response.text[:200]}")
                
                else:
                    # Unexpected status code
                    print(f"Unexpected response: {response.text[:200]}")
                    response.failure(f"Checkout failed with status {response.status_code}")

        except Exception as e:
            print(f"Exception during checkout: {str(e)}")
            raise


    @task(1)
    def view_valid_order(self):
        """Test viewing a valid order confirmation"""
        if hasattr(self, 'order_id') and self.order_id:
            with self.client.get(
                f"/order-confirmation/{self.order_id}",
                catch_response=True,
                allow_redirects=True
            ) as response:
                if response.status_code == 200:
                    if "Order Confirmation" in response.text and str(self.order_id) in response.text:
                        # Silent success - no logging
                        response.success()
                    else:
                        # Only log actual failures
                        response.failure("Order confirmation content not found")
                else:
                    # Only log unexpected status codes
                    response.failure(f"Status code {response.status_code}")

    # This task runs really infrequently because it just destroys the UI otherwise.
    @task(200)
    def view_invalid_order(self):
        """Test viewing an invalid order confirmation"""
        invalid_order_id = "INVALID" + str(random.randint(1000, 9999))
        with self.client.get(
            f"/order-confirmation/{invalid_order_id}",
            catch_response=True,
            allow_redirects=True
        ) as response:
            if response.status_code == 200:  # Should land on index page
                if "Order not found" in response.text:
                    # Silent success - no logging
                    response.success()
                else:
                    # Only log actual failures
                    response.failure("Flash message missing")
            else:
                # Only log unexpected status codes
                response.failure(f"Status code {response.status_code}")

    @task(2)
    def add_to_cart(self):
        book_titles = ["The Great Gatsby", "1984", "I Ching", "Moby Dick"]
        book_title = random.choice(book_titles)
        self.client.post("/add-to-cart", data={
            "title": book_title,
            "quantity": 1
        }, allow_redirects=True)
    
    @task(2)
    def view_cart(self):
        self.client.get("/cart")

    @task(2)
    def homepage(self):
        self.client.get("/")

    