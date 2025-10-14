import unittest
from time import perf_counter
from models import Book, Cart, CartItem, User, Order, PaymentGateway, EmailService
from app import app, apply_discount

def workflow_timer(func):
    """Decorator to time workflow execution for CI/CD metrics"""
    def wrapper(*args, **kwargs):
        start = perf_counter()
        result = func(*args, **kwargs)
        duration = perf_counter() - start
        print(f"\nWorkflow '{func.__name__}' completed in {duration:.3f} seconds")
        return result
    return wrapper

class IntegrationTests(unittest.TestCase):
    """Integration tests simulating complete workflows between model components"""
    
    def setUp(self):
        """Initialize test data"""
        # Create sample books
        self.books = [
            Book("Test Book 1", "Fiction", 10.99, "/images/test1.jpg"),
            Book("Test Book 2", "Non-Fiction", 15.99, "/images/test2.jpg"),
            Book("Test Book 3", "Mystery", 12.99, "/images/test3.jpg")
        ]
        
        # Create test user
        self.test_user = User(
            "test@example.com",
            "password123",
            "Test User",
            "123 Test St"
        )
        # Setup Flask test client
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test_secret_key'
        self.client = app.test_client()
        
        # Initialize fresh cart for each test
        self.cart = Cart()

        

# INT-001: Test complete order workflow
# Steps:
# 1. Add books to cart
# 2. Verify cart state
# 3. Create order from cart
# 4. Process payment
# 5. Send email confirmation
# Expected: Order created, payment processed, email sent
    @workflow_timer
    def test_complete_order_workflow(self):
        """Test full order workflow from cart creation to order completion"""
        # 1. Add books to cart
        self.cart.add_book(self.books[0], 2)
        self.cart.add_book(self.books[1], 1)
        
        # 2. Verify cart state
        self.assertEqual(len(self.cart.get_items()), 2)
        expected_total = (self.books[0].price * 2) + (self.books[1].price * 1)
        self.assertEqual(self.cart.get_total_price(), expected_total)
        
        # 3. Create order from cart
        shipping_info = {
            "name": self.test_user.name,
            "address": self.test_user.address,
            "email": self.test_user.email
        }
        
        payment_info = {
            "payment_method": "credit_card",
            "card_number": "4111111111112222"
        }
        
        order = Order(
            "TEST123",
            self.test_user.email,
            self.cart.get_items(),
            shipping_info,
            payment_info,
            self.cart.get_total_price()
        )
        
        # 4. Verify order creation
        self.assertEqual(order.status, "Confirmed")
        self.assertEqual(order.total_amount, expected_total)

        # 5. Process payment
        payment_result = PaymentGateway.process_payment(payment_info)
        self.assertTrue(payment_result['success'])
        self.assertIsNotNone(payment_result['transaction_id'])
        
        # 6. Send confirmation email
        email_result = EmailService.send_order_confirmation(
            self.test_user.email,
            order.to_dict()
        )
        self.assertTrue(email_result)


# INT-002: Test user registration and order history tracking
# Steps:
# 1. Register User
# 2. Add orders to user
# 3. Verify order history retrieval
# Expected: User can register and retrieve order history
    @workflow_timer
    def test_user_registration_and_order_history(self):
        # 1. Create new user (simulating registration)
        new_user = User(
            "newuser@test.com",
            "securepass123",
            "New User",
            "456 New St"
        )
        
        self.assertEqual(new_user.email, "newuser@test.com")
        self.assertEqual(new_user.name, "New User")
        
        # 2. Create first order
        self.cart.add_book(self.books[0], 1)
        order1 = Order(
            "TEST002",
            new_user.email,
            self.cart.get_items(),
            {"address": new_user.address},
            {"payment_method": "paypal"},
            self.cart.get_total_price()
        )
        
        new_user.add_order(order1)
        
        # 3. Verify first order in history
        history = new_user.get_order_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].order_id, "TEST002")
        
        # 4. Create second order
        self.cart.clear()
        self.cart.add_book(self.books[1], 2)
        order2 = Order(
            "TEST003",
            new_user.email,
            self.cart.get_items(),
            {"address": new_user.address},
            {"payment_method": "credit_card"},
            self.cart.get_total_price()
        )
        
        new_user.add_order(order2)
        
        # 5. Verify order history with multiple orders
        history = new_user.get_order_history()
        self.assertEqual(len(history), 2)
        # Orders should be sorted by date
        self.assertIsNotNone(history[0].order_date)
        self.assertIsNotNone(history[1].order_date)



# INT-003: Test payment processing and email notification integration
# Steps: 
# 1. Setup order
# 2. Process payment
# 3. Send email confirmation
# Expected: Payment processed and email sent successfully
    @workflow_timer
    def test_payment_and_email_workflow(self):
        # 1. Setup order
        self.cart.add_book(self.books[0], 1)
        order = Order(
            "TEST004",
            self.test_user.email,
            self.cart.get_items(),
            {"address": self.test_user.address},
            {"payment_method": "credit_card", "card_number": "4111111111112222"},
            self.cart.get_total_price()
        )
        
        # 2. Process payment with valid card
        payment_result = PaymentGateway.process_payment(order.payment_info)
        self.assertTrue(payment_result['success'])
        self.assertEqual(payment_result['message'], 'Payment processed successfully')
        self.assertIsNotNone(payment_result['transaction_id'])
        
        # 3. Test PayPal payment method
        paypal_info = {"payment_method": "paypal", "paypal_email": "user@paypal.com"}
        paypal_result = PaymentGateway.process_payment(paypal_info)
        self.assertTrue(paypal_result['success'])
        
        # 4. Send email confirmation
        order_dict = order.to_dict()
        email_result = EmailService.send_order_confirmation(
            self.test_user.email,
            order_dict
        )
        self.assertTrue(email_result)
        
        # 5. Test failed payment (card ending in 1111)
        failed_payment_info = {"payment_method": "credit_card", "card_number": "4111111111111111"}
        failed_result = PaymentGateway.process_payment(failed_payment_info)
        self.assertFalse(failed_result['success'])

# INT-004: Test cart edge cases
# Steps:
# 1. Add same book multiple times
# 2. Remove and re-add
# 3. Clear cart
# Expected: Cart behaves correctly in all edge cases
    def test_cart_operations_workflow(self):
        # 1. Add multiple different items
        self.cart.add_book(self.books[0], 2)
        self.cart.add_book(self.books[1], 1)
        self.cart.add_book(self.books[2], 3)
        
        self.assertEqual(len(self.cart.get_items()), 3)
        self.assertEqual(self.cart.get_total_items(), 6)
        
        # 2. Add same book again (should increase quantity)
        self.cart.add_book(self.books[0], 1)
        items = self.cart.get_items()
        book1_item = next(item for item in items if item.book.title == "Test Book 1")
        self.assertEqual(book1_item.quantity, 3)
        
        # 3. Update quantity
        self.cart.update_quantity("Test Book 2", 5)
        items = self.cart.get_items()
        book2_item = next(item for item in items if item.book.title == "Test Book 2")
        self.assertEqual(book2_item.quantity, 5)
        
        # 4. Remove one item
        self.cart.remove_book("Test Book 3")
        self.assertEqual(len(self.cart.get_items()), 2)
        
        # 5. Verify total price calculation
        expected_total = (self.books[0].price * 3) + (self.books[1].price * 5)
        self.assertAlmostEqual(self.cart.get_total_price(), expected_total)
        
        # 6. Clear cart
        self.cart.clear()
        self.assertTrue(self.cart.is_empty())
        self.assertEqual(self.cart.get_total_items(), 0)

# INT-005: Test user profile management
# Steps:
# 1. Create user
# 2. Update profile details
# 3. Verify changes
# Expected: User details updated correctly, XSS protection in place
    def test_user_profile_management(self):
        # 1. Create user with initial data
        user = User(
            "profile@test.com",
            "password123",
            "Original Name",
            "Original Address"
        )
        
        self.assertEqual(user.name, "Original Name")
        self.assertEqual(user.address, "Original Address")
        
        # 2. Simulate profile update
        user.name = "Updated Name"
        user.address = "Updated Address"
        
        # 3. Verify changes
        self.assertEqual(user.name, "Updated Name")
        self.assertEqual(user.address, "Updated Address")
        
        # 4. Verify email remains unchanged (should be immutable)
        original_email = user.email
        self.assertEqual(user.email, "profile@test.com")
        
        # 5. Test XSS protection in name/address (HTML escaping)
        xss_user = User(
            "xss@test.com",
            "pass",
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>"
        )
        self.assertNotIn("<script>", xss_user.name)
        self.assertNotIn("<img", xss_user.address)

# INT-006: Performance test for large order processing
# Steps:
# 1. Create large order with many items
# 2. Measure processing time
# Expected: Order processed within acceptable time limits
    @workflow_timer
    def test_order_processing_performance(self):
        # 1. Create large order with multiple books
        start_time = perf_counter()
        
        for i in range(10):
            book = Book(f"Performance Book {i}", "Test", 9.99, "/test.jpg")
            self.cart.add_book(book, 5)
        
        # 2. Verify cart contents
        self.assertEqual(len(self.cart.get_items()), 10)
        self.assertEqual(self.cart.get_total_items(), 50)
        
        # 3. Calculate total
        total = self.cart.get_total_price()
        expected_total = 9.99 * 50
        self.assertAlmostEqual(total, expected_total, places=2)
        
        # 4. Create order
        order = Order(
            "PERF001",
            self.test_user.email,
            self.cart.get_items(),
            {"address": "Test Address"},
            {"payment_method": "credit_card", "card_number": "4111111111112222"},
            total
        )
        
        # 5. Process payment
        payment_result = PaymentGateway.process_payment(order.payment_info)
        self.assertTrue(payment_result['success'])
        
        end_time = perf_counter()
        processing_time = end_time - start_time
        
        # 6. Verify performance (should complete in reasonable time)
        self.assertLess(processing_time, 5.0, "Order processing took too long")
        print(f"Large order processed in {processing_time:.3f} seconds")

# INT-007: Security integration tests
# Steps:
# 1. Test XSS protection in user inputs
# 2. Test session security in Flask app
# Expected: Inputs are sanitized, sessions are secure
    def test_security_integration(self):
        # 1. Test XSS protection in user input
        malicious_name = "<script>alert('XSS')</script>"
        malicious_address = "<img src=x onerror=alert('XSS')>"
        
        secure_user = User(
            "secure@test.com",
            "password",
            malicious_name,
            malicious_address
        )
        
        # Verify HTML is escaped
        self.assertNotIn("<script>", secure_user.name)
        self.assertNotIn("<img", secure_user.address)
        self.assertIn("&lt;", secure_user.name)  # Should contain escaped HTML
        
        # 2. Test that book data doesn't allow script injection
        safe_book = Book(
            "<script>alert('book')</script>",
            "Fiction",
            10.99,
            "/image.jpg"
        )
        # Book title should be stored as-is (sanitization happens at display)
        self.assertIn("script", safe_book.title)
        
        # 3. Test session security with Flask app
        with self.client as client:
            # Verify session is empty initially
            with client.session_transaction() as sess:
                self.assertNotIn('user_email', sess)
            
            # Test login route
            response = client.post('/login', data={
                'email': 'demo@bookstore.com',
                'password': 'demo123'
            }, follow_redirects=True)
            
            # Verify session is set after login
            with client.session_transaction() as sess:
                self.assertEqual(sess.get('user_email'), 'demo@bookstore.com')


# INT-008: Test discount code application during checkout
# Steps:
# 1. Add items to cart
# 2. Apply discount code
# 3. Verify discounted total
# Expected: Discount applied correctly, total updated
    def test_discount_code_integration(self):
        # 1. Add items to cart
        self.cart.add_book(self.books[0], 2)  # $21.98
        self.cart.add_book(self.books[1], 1)  # $15.99
        
        original_total = self.cart.get_total_price()
        self.assertAlmostEqual(original_total, 37.97, places=2)
        
        # 2. Apply 10% discount (SAVE10)
        discount_result = apply_discount('SAVE10', self.cart)
        
        # The discount_result should contain:
        # - total_amount: the DISCOUNTED amount (after discount is applied)
        # - discount_applied: the amount of discount
        
        expected_discount = round(original_total * 0.10, 2)
        expected_final_total = original_total - expected_discount
        
        self.assertAlmostEqual(discount_result['discount_applied'], expected_discount, places=2)
        self.assertAlmostEqual(discount_result['total_amount'], expected_final_total, places=2)
        
        # 3. Test case-insensitive discount code
        discount_result_lower = apply_discount('save10', self.cart)
        self.assertAlmostEqual(discount_result['discount_applied'], discount_result_lower['discount_applied'], places=2)
        self.assertAlmostEqual(discount_result['total_amount'], discount_result_lower['total_amount'], places=2)
        
        # 4. Test 20% discount (WELCOME20)
        self.cart.clear()
        self.cart.add_book(self.books[0], 1)  # $10.99
        discount_result_20 = apply_discount('WELCOME20', self.cart)
        expected_discount_20 = round(10.99 * 0.20, 2)
        expected_final_20 = 10.99 - expected_discount_20
        
        self.assertAlmostEqual(discount_result_20['discount_applied'], expected_discount_20, places=2)
        self.assertAlmostEqual(discount_result_20['total_amount'], expected_final_20, places=2)
        
        # 5. Test invalid discount code
        invalid_result = apply_discount('INVALID', self.cart)
        self.assertEqual(invalid_result['discount_applied'], 0)
        self.assertAlmostEqual(invalid_result['total_amount'], 10.99, places=2)
        
        # 6. Test empty discount code
        empty_result = apply_discount('', self.cart)
        self.assertEqual(empty_result['discount_applied'], 0)
        self.assertAlmostEqual(empty_result['total_amount'], 10.99, places=2)

# INT-009: Test email notification chain
# Steps:
# 1. Create and complete order
# 2. Send order confirmation email
# 3. Verify email content
# Expected: Email sent with correct order details

    def test_email_notification_chain(self):
        # 1. Create and complete order
        self.cart.add_book(self.books[0], 1)
        order = Order(
            "EMAIL001",
            self.test_user.email,
            self.cart.get_items(),
            {"name": self.test_user.name, "address": self.test_user.address},
            {"payment_method": "credit_card", "card_number": "4111111111112222"},
            self.cart.get_total_price()
        )
        
        # 2. Send order confirmation
        order_dict = order.to_dict()
        confirmation_sent = EmailService.send_order_confirmation(
            self.test_user.email,
            order_dict
        )
        self.assertTrue(confirmation_sent)
        
        # 3. Verify order details in dict format
        self.assertEqual(order_dict['order_id'], "EMAIL001")
        self.assertEqual(order_dict['user_email'], self.test_user.email)
        self.assertEqual(order_dict['status'], "Confirmed")
        self.assertIn('order_date', order_dict)
        self.assertIn('items', order_dict)
        
        # 4. Verify items structure in order
        self.assertEqual(len(order_dict['items']), 1)
        self.assertEqual(order_dict['items'][0]['title'], "Test Book 1")
        self.assertEqual(order_dict['items'][0]['quantity'], 1)

# INT-010: Test session management in Flask app
# Steps:
# 1. Login user
# 2. Verify session is set
# 3. Access protected route
# 4. Logout user
# 5. Verify session is cleared
# Expected: Session behaves correctly through login/logout cycle
    def test_session_management_integration(self):
        with self.client as client:
            # 1. Test login
            response = client.post('/login', data={
                'email': 'demo@bookstore.com',
                'password': 'demo123'
            }, follow_redirects=True)
            
            self.assertEqual(response.status_code, 200)
            
            # 2. Verify session is set
            with client.session_transaction() as sess:
                self.assertEqual(sess.get('user_email'), 'demo@bookstore.com')
            
            # 3. Test protected route access (account page)
            response = client.get('/account')
            self.assertEqual(response.status_code, 200)
            
            # 4. Perform cart operation while logged in
            response = client.post('/add-to-cart', data={
                'title': 'The Great Gatsby',
                'quantity': 1
            }, follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # 5. Test logout
            response = client.get('/logout', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # 6. Verify session is cleared
            with client.session_transaction() as sess:
                self.assertNotIn('user_email', sess)
            
            # 7. Test protected route after logout (should redirect)
            response = client.get('/account', follow_redirects=False)
            self.assertEqual(response.status_code, 302)  # Redirect


if __name__ == '__main__':
    unittest.main(verbosity=2)