from time import perf_counter
import unittest
import timeit
import cProfile
import io
import pstats
from app import app, cart, BOOKS, get_book_by_title, apply_discount, users
from models import Book, Cart, PaymentGateway, EmailService, Order, CartItem, User
from unittest.mock import patch, MagicMock, Mock

class OnlineBookstoreTests(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        # Reset the global cart before every test
        cart.clear()
        # Reset the global users dictionary before every test
        users.clear()
        # Re-add demo user since it's part of the app's initial state
        users["demo@bookstore.com"] = User("demo@bookstore.com", "demo123", "Demo User", "123 Demo Street, Demo City, DC 12345")

# ---------------- Book Browsing & Search Tests ----------------

# Not linked to a specific test case, but a basic sanity check
    def test_browse_all_books_homepage(self):
        resp = self.app.get('/')
        self.assertEqual(resp.status_code, 200)
        for book in BOOKS:
            # Each book title should be rendered somewhere on the page
            self.assertIn(book.title.encode(), resp.data)

# TC-001: Verify browsing books by category displays correct books
    def test_filter_books_by_category(self):
        """TC-001: Filter logic by category—ensure at least one Fiction book exists."""
        fiction_books = [b for b in BOOKS if b.category == "Fiction"]
        self.assertTrue(len(fiction_books) > 0, "No books found in Fiction category")

# TC-002: Verify searching for a book by title returns correct results
    def test_search_book_by_title_helper(self):
        """TC-002: Search by exact title returns the correct book via helper function."""
        target_title = BOOKS[0].title
        found = get_book_by_title(target_title)
        self.assertIsNotNone(found)
        self.assertEqual(found.title, target_title)

# TC-003: Verify searching for an author returns correct results
    @unittest.skip("Books do not have an author attribute, this test is skipped until author data is added.")
    def test_search_books_by_author(self):
        """TC-004: Search by author returns all books by that author."""
        target_author = BOOKS[0].author
        author_books = [b for b in BOOKS if b.author == target_author]
        self.assertTrue(len(author_books) > 0, "No books found for the given author")

# TC-005: Verify searching for a non-existent book returns no results
    def test_search_non_existent_book(self):
        """TC-003: Search for a non-existent book returns no results."""
        non_existent_title = "This Book Does Not Exist"
        found = get_book_by_title(non_existent_title)
        self.assertIsNone(found)

# ---------------- Shopping Cart Tests ----------------

# TC-006: Verify adding a book to the cart updates the cart contents
    def test_add_book_to_cart(self):
        """TC-006: Adding a book to the cart updates cart contents."""
        book = BOOKS[0]
        expected_cost = book.price * 1
        cart.add_book(book, quantity=1)
        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].book.title, book.title)
        self.assertEqual(items[0].quantity, 1)
        self.assertEqual(cart.get_total_price(), expected_cost)

# TC-007: Verify adding multiple different books to the cart updates the cart correctly
    def test_add_multiple_different_books_to_cart(self):
        """TC-007: Adding multiple different books to the cart updates cart correctly."""
        book1 = BOOKS[0]
        book2 = BOOKS[1]
        cart.add_book(book1, quantity=1)
        cart.add_book(book2, quantity=1)
        expected_cost = book1.price + book2.price
        items = cart.get_items()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].book.title, book1.title)
        self.assertEqual(items[0].quantity, 1)
        self.assertEqual(items[1].book.title, book2.title)
        self.assertEqual(items[1].quantity, 1)
        self.assertEqual(cart.get_total_price(), expected_cost)

# TC-008: Verify increasing the quantity of an existing book in the cart updates the quantity correctly
    def test_increase_quantity_of_existing_book_in_cart(self):
        """TC-008: Increasing quantity of an existing book in the cart updates quantity correctly."""
        book = BOOKS[0]
        expected_cost = book.price * 3
        cart.add_book(book, quantity=1)
        cart.add_book(book, quantity=2)  # Add same book again
        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].book.title, book.title)
        self.assertEqual(items[0].quantity, 3)  # Total quantity should be 3
        self.assertEqual(cart.get_total_price(), expected_cost)

# TC-009: Verify removing a book from the cart updates the cart contents
    def test_remove_book_from_cart(self):
        """TC-009: Removing a book from the cart updates cart contents."""
        book = BOOKS[0]
        cart.add_book(book, quantity=1)
        cart.remove_book(book.title)
        items = cart.get_items()
        self.assertEqual(len(items), 0)
        self.assertEqual(cart.get_total_price(), 0)


# TC-010: Verify decreasing the quantity of a book in the cart updates the quantity correctly
    def test_decrease_quantity_of_book_in_cart(self):
        """TC-010: Decreasing quantity of a book in the cart updates quantity correctly."""
        book = BOOKS[0]
        expected_cost = book.price * 1
        cart.add_book(book, quantity=3)
        cart.update_quantity(book.title, 1)  # Decrease quantity to 1
        items = cart.get_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].quantity, 1)
        self.assertEqual(cart.get_total_price(), expected_cost)

# TC-011: Verify clearing the cart removes all items
    def test_clear_cart(self):
        """TC-011: Clearing the cart removes all items."""
        book1 = BOOKS[0]
        book2 = BOOKS[1]
        cart.add_book(book1, quantity=1)
        cart.add_book(book2, quantity=1)
        cart.clear()
        items = cart.get_items()
        self.assertEqual(len(items), 0)
        self.assertEqual(cart.get_total_price(), 0)
        self.assertTrue(cart.is_empty())


# TC-012: Verify invalid quantity updates are handled gracefully
    def test_invalid_quantity_update_in_cart(self):
        """TC-012: Invalid quantity updates are handled gracefully."""
        book = BOOKS[0]
        cart.add_book(book, quantity=2)
        # Attempt to set a negative quantity
        cart.update_quantity(book.title, -1)
        items = cart.get_items()
        # Quantity should remain unchanged
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].quantity, 2)
        self.assertEqual(cart.get_total_price(), book.price * 2)


# Route Tests
# These ensure the Flask routes behave as expected, focusing on HTTP responses and flash messages.
# These will be made a little redundant by integration tests but its a sanity check.
    def test_add_to_cart_route(self):
        resp = self.app.post('/add-to-cart', data={'title': BOOKS[0].title, 'quantity': 1}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Added', resp.data)
        self.assertEqual(cart.get_total_items(), 1)
    
    def test_remove_from_cart_route(self):
        cart.add_book(BOOKS[0], 1)
        resp = self.app.post('/remove-from-cart', data={'title': BOOKS[0].title}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(cart.is_empty())
    
    def test_update_cart_route(self):
        cart.add_book(BOOKS[0], 1)
        resp = self.app.post('/update-cart', data={'title': BOOKS[0].title, 'quantity': 3}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(cart.get_total_items(), 3)
# ----------------- Checkout && Payment Process Tests -----------------

# TC-013: Verify checkout summary shows correct total and items
    def test_checkout_summary(self):
        book1 = BOOKS[0]
        book2 = BOOKS[1]
        cart.add_book(book1, quantity=2)
        cart.add_book(book2, quantity=1)
        expected_total = book1.price * 2 + book2.price * 1
        resp = self.app.get('/checkout')
        self.assertEqual(resp.status_code, 200)
        self.assertIn(str(expected_total).encode(), resp.data)
        self.assertIn(book1.title.encode(), resp.data)
        self.assertIn(book2.title.encode(), resp.data)

# TC-014: Verify checkout with empty cart redirects to homepage
    def test_checkout_with_empty_cart(self):
        resp = self.app.get('/checkout', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Your cart is empty', resp.data)

# TC-015: Test the Mock Payment Gateway Fails for cards ending in 1111
    def test_mock_payment_gateway(self):
        payment_info = {
            'payment_method': 'Not PayPal',
            'card_number': '4111 1111 1111 1111',
            'expiry_date': '12/30',
            'cvv': '123'
        }
        result = PaymentGateway.process_payment(payment_info)
        self.assertFalse(result['success'])
        self.assertEqual(result['message'], 'Payment failed: Invalid card number')
        self.assertIn('transaction_id', result)

# TC-016: Test the Mock Payment Gateway Succeeds for valid cards
    def test_mock_payment_gateway_success(self):
        payment_info = {
            'payment_method': 'Not PayPal',
            'card_number': '4111 1111 1111 1234',
            'expiry_date': '12/30',
            'cvv': '123'
        }
        result = PaymentGateway.process_payment(payment_info)
        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'Payment processed successfully')
        self.assertIsNotNone(result['transaction_id'])

# TC-017: Verify Payment with PayPal option
    def test_payment_with_paypal_option(self):
        payment_info = {
            'payment_method': 'paypal',
            'card_number': '4111 1111 1111 1234',  # Card number is irrelevant for PayPal in this mock
            'expiry_date': '12/30',
            'cvv': '123'
        }
        result = PaymentGateway.process_payment(payment_info)
        self.assertTrue(result['success'])
        self.assertEqual(result['message'], 'Payment processed successfully')
        self.assertIsNotNone(result['transaction_id'])  

# TC-018: Verify email sending function (mock)
    def test_email_sending_function(self):
        order = {
            'order_id': 'ORD123456',
            'order_date': '2024-01-01 12:00:00',
            'items': [{'title': BOOKS[0].title, 'quantity': 1, 'price': BOOKS[0].price}],
            'total_amount': BOOKS[0].price,
            'shipping_info': {
                'name': 'Test User',
                'address': '123 Test St',
                'city': 'Testville'
            }
        }
        user_email = 'testemail@gmail.com'
        result = EmailService.send_order_confirmation(user_email, order)
        self.assertTrue(result)

# TC-019: Verify discount code logic applies correct discount
    def test_discount_code_logic(self):
        discount_code = 'SAVE10'
        book = BOOKS[0]
        cart.add_book(book, quantity=1)
        original_total = cart.get_total_price()
        discount_info = apply_discount(discount_code, cart)
        expected_total = original_total * 0.90  # 10% off
        self.assertEqual(discount_info['discount_applied'], original_total * 0.10)
        self.assertEqual(discount_info['total_amount'], expected_total)

# TC-020: Verify invalid discount code is handled gracefully
    def test_invalid_discount_code(self):
        discount_code = 'INVALIDCODE'
        book = BOOKS[0]
        cart.add_book(book, quantity=1)
        original_total = cart.get_total_price()
        discount_info = apply_discount(discount_code, cart)
        # No discount should be applied
        self.assertEqual(discount_info['discount_applied'], 0)
        self.assertEqual(discount_info['total_amount'], original_total)
            
# TC-021: Verify transportation security (HTTPS) is enforced for checkout and payment routes
    @unittest.skip("HTTPS enforcement requires server configuration, this test is skipped.")
    def test_https_enforced_for_checkout_and_payment(self):
        # Simulate a non-HTTPS request to checkout
        resp = self.app.get('/checkout', base_url='http://localhost')
        self.assertEqual(resp.status_code, 302)  # Should redirect to HTTPS
        self.assertIn('https://', resp.location)

        # Simulate a non-HTTPS request to payment
        resp = self.app.post('/process-checkout', data={}, base_url='http://localhost')
        self.assertEqual(resp.status_code, 302)  # Should redirect to HTTPS
        self.assertIn('https://', resp.location)


# TC-022: Verify Order Confirmation page does not display when invalid order ID is provided
    def test_order_confirmation_invalid_order_id(self):
        resp = self.app.get('/order-confirmation/INVALID_ID', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Order not found', resp.data)

    @patch('app.get_current_user')
    @patch('app.orders') 
    def test_order_confirmation_valid_order(self, mock_orders, mock_get_current_user):
        # Create actual Order object
        order_id = 'ORD123456'
        test_book = BOOKS[0]
        cart_item = CartItem(test_book, 1)
        
        mock_order = Order(
            order_id=order_id,
            user_email='test@example.com',
            items=[cart_item],
            shipping_info={
                'name': 'Test User',
                'address': '123 Test St',
                'city': 'Testville'
            },
            payment_info={
                'method': 'credit_card',
                'transaction_id': 'TXN123'
            },
            total_amount=test_book.price
        )

        # Mock user with the order
        mock_user = MagicMock()
        mock_user.orders = [mock_order]
        mock_get_current_user.return_value = mock_user

        # Mock the global orders dictionary to return our mock order
        mock_orders.get.return_value = mock_order

        resp = self.app.get(f"/order-confirmation/{order_id}", follow_redirects=True)
        
        self.assertEqual(resp.status_code, 200)
        self.assertIn(order_id.encode(), resp.data)
        self.assertIn(str(test_book.price).encode(), resp.data)

# TC-023: Verify Email Confirmation is sent upon successful order placement
    @patch('app.EmailService.send_order_confirmation')
    @patch('app.get_current_user')
    @patch('app.PaymentGateway.process_payment')
    def test_email_confirmation_sent_on_order(self, mock_payment, mock_get_current_user, mock_send_email):
        # Setup mock user
        mock_user = MagicMock()
        mock_user.email = 'test@gmail.com'
        mock_get_current_user.return_value = mock_user

        # Setup mock payment success
        mock_payment.return_value = {
            'success': True,
            'message': 'Payment processed successfully',
            'transaction_id': 'TEST123'
        }

        # Setup mock email service
        mock_send_email.return_value = True

        # Add item to cart
        book = BOOKS[0]
        cart.add_book(book, quantity=1)

        # Simulate checkout form data
        checkout_data = {
            'name': 'Test User',
            'email': 'test@gmail.com',
            'address': '123 Test St',
            'city': 'Testville',
            'zip_code': '12345',
            'payment_method': 'credit_card',
            'card_number': '4111 1111 1111 1234',
            'expiry_date': '12/30',
            'cvv': '123'
        }

        # Process checkout
        resp = self.app.post('/process-checkout', data=checkout_data, follow_redirects=True)

        # Verify response and email sending
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b'Order Confirmation - Online Bookstore', resp.data)
        # Checks we are emailing the correct user
        self.assertIn(b'test@gmail.com', resp.data)
        mock_send_email.assert_called_once()

        # Clean up
        cart.clear()

# -------------------- User Management Tests --------------------
# TC-024: Verify user registration with valid data
    def test_user_registration_valid_data(self):
        """Test user registration with complete valid data"""
        test_user_data = {
            'email': 'newuser@test.com',
            'password': 'securepass123',
            'name': 'New User',
            'address': '123 Test Street'
        }
        
        response = self.app.post('/register', 
                               data=test_user_data, 
                               follow_redirects=True)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Account created successfully', response.data)
        
        # Verify user was created and stored
        self.assertIn('newuser@test.com', users)
        created_user = users['newuser@test.com']
        self.assertEqual(created_user.email, test_user_data['email'])
        self.assertEqual(created_user.name, test_user_data['name'])
        self.assertEqual(created_user.address, test_user_data['address'])
        
        # Verify user is logged in (session contains email)
        with self.app as c:
            with c.session_transaction() as sess:
                self.assertEqual(sess['user_email'], 'newuser@test.com')

# TC-025: Verify duplicate email registration is prevented
    def test_user_registration_duplicate_email(self):
        """Test registration with an email that already exists"""
        # First create a user
        test_user_data = {
            'email': 'duplicate@test.com',
            'password': 'password123',
            'name': 'Original User',
            'address': '123 Test St'
        }
        self.app.post('/register', data=test_user_data)
        
        # Try to create another user with the same email
        duplicate_user_data = {
            'email': 'duplicate@test.com',
            'password': 'different123',
            'name': 'Duplicate User',
            'address': '456 Test Ave'
        }
        
        response = self.app.post('/register', 
                               data=duplicate_user_data, 
                               follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'An account with this email already exists', response.data)
        
        # Verify the original user wasn't modified
        stored_user = users['duplicate@test.com']
        self.assertEqual(stored_user.name, 'Original User')
        # Verify password by checking it matches (since passwords are now hashed)
        self.assertTrue(stored_user.check_password('password123'))

# TC-026: Verify registration fails with missing required fields
    def test_user_registration_missing_fields(self):
        """Test registration with missing required fields"""
        test_cases = [
            {
                'data': {'password': 'pass123', 'name': 'Test User'},
                'missing': 'email'
            },
            {
                'data': {'email': 'test@test.com', 'name': 'Test User'},
                'missing': 'password'
            },
            {
                'data': {'email': 'test@test.com', 'password': 'pass123'},
                'missing': 'name'
            }
        ]
        
        for test_case in test_cases:
            response = self.app.post('/register', 
                                   data=test_case['data'], 
                                   follow_redirects=True)
            
            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Please fill in all required fields', response.data)
            
            # Verify no user was created
            if 'email' in test_case['data']:
                self.assertNotIn(test_case['data']['email'], users)

# TC-027: Verify already existing user can log in with correct credentials using Demo User
    def test_user_login_valid_credentials(self):
        """Test login with valid credentials"""
        # First ensure the demo user exists
        demo_email = "demo@bookstore.com"
        demo_password = "demo123"
        self.assertIn(demo_email, users)
        demo_user = users[demo_email]
        # Verify password is hashed and can be checked
        self.assertTrue(demo_user.check_password(demo_password))
        response = self.app.post('/login', 
                               data={'email': demo_email, 'password': demo_password}, 
                               follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Logged in successfully', response.data)
        # Verify session contains user email
        with self.app as c:
            with c.session_transaction() as sess:
                self.assertEqual(sess['user_email'], demo_email)

# TC-028: Verify login fails with incorrect credentials
    def test_user_login_invalid_credentials(self):
        """Test login with incorrect credentials"""
        # Ensure the demo user exists
        demo_email = "demo@bookstore.com"
        demo_password = "demo1234" # Incorrect password
        self.assertIn(demo_email, users)
        response = self.app.post('/login', 
                               data={'email': demo_email, 'password': demo_password}, 
                               follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid email or password', response.data)
        # Verify session does not contain user email
        with self.app as c:
            with c.session_transaction() as sess:
                self.assertNotIn('user_email', sess)

# TC-029: Verify a logged-in user can log out successfully
    def test_user_logout(self):
        """Test logout functionality"""
        # First log in the demo user
        demo_email = "demo@bookstore.com"
        demo_password = "demo123"
        self.app.post('/login', 
                      data={'email': demo_email, 'password': demo_password}, 
                      follow_redirects=True)
        # Now log out
        response = self.app.get('/logout', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Logged out successfully', response.data)
        # Verify session no longer contains user email
        with self.app as c:
            with c.session_transaction() as sess:
                self.assertNotIn('user_email', sess)

# TC-030: Verify a logged-in user can access their order history
    def test_user_order_history_access(self):
        """Test that a logged-in user can access their order history"""
        # Create a test user
        test_user = User("test@example.com", "password123", "Test User", "123 Test St")
        
        # Create test order
        order_id = 'ORD123456'
        test_book = BOOKS[0]
        cart_item = CartItem(test_book, 1)
        
        test_order = Order(
            order_id=order_id,
            user_email='test@example.com',
            items=[cart_item],
            shipping_info={
                'name': 'Test User',
                'address': '123 Test St',
                'city': 'Testville'
            },
            payment_info={
                'method': 'credit_card',
                'transaction_id': 'TXN123'
            },
            total_amount=test_book.price
        )
        
        # Add order to user's order history
        test_user.add_order(test_order)
        
        # Get order history
        order_history = test_user.get_order_history()
        
        # Verify order history
        self.assertEqual(len(order_history), 1)
        self.assertEqual(order_history[0].order_id, order_id)
        self.assertEqual(order_history[0].user_email, 'test@example.com')
        self.assertEqual(len(order_history[0].items), 1)
        self.assertEqual(order_history[0].items[0].book.title, test_book.title)
        self.assertEqual(order_history[0].total_amount, test_book.price)


# TC-031: Verify a logged in user can update their profile information
    def test_user_profile_update(self):
        """Test that a logged-in user can update their profile information"""
        # First log in the demo user
        demo_email = "demo@bookstore.com"
        demo_password = "demo123"
        self.app.post('/login', 
                      data={'email': demo_email, 'password': demo_password}, 
                      follow_redirects=True)
        # Update profile information
        updated_info = {
            'name': 'Updated Demo User',
            'address': '456 New Address, New City, NC 67890'
        }
        response = self.app.post('/update-profile', 
                                 data=updated_info, 
                                 follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Profile updated successfully', response.data)
        # Verify the user's information was updated
        updated_user = users[demo_email]
        self.assertEqual(updated_user.name, updated_info['name'])
        self.assertEqual(updated_user.address, updated_info['address'])

# TC-032: Verify a logged in user cannot see another user's order history
    def test_user_cannot_see_others_order_history(self):
        """Test that a user cannot see another user's order history"""
        # Create two users
        user1_password = "demo1234"
        user2_password = "demo1235"
        user1 = User("demo@bookstore1.com", user1_password, "Demo User Uno", "1234 Demo Street, Demo City, DC 12345")
        user2 = User("demo@bookstore2.com", user2_password, "Demo User Dos", "1235 Demo Street, Demo City, DC 12345")
        users[user1.email] = user1
        users[user2.email] = user2
        # Create an order for user1
        order_id = 'ORD654321'
        test_book = BOOKS[0]
        cart_item = CartItem(test_book, 1)
        test_order = Order(
            order_id=order_id,
            user_email=user1.email,
            items=[cart_item],
            shipping_info={
                'name': user1.name,
                'address': user1.address,
                'city': 'Testville'
            },
            payment_info={
                'method': 'credit_card',
                'transaction_id': 'TXN456'
            },
            total_amount=test_book.price
        )
        user1.add_order(test_order)
        # Log in as user2
        self.app.post('/login', 
                      data={'email': user2.email, 'password': user2_password}, 
                      follow_redirects=True)
        # Attempt to access user1's order confirmation page
        response = self.app.get(f'/order-confirmation/{order_id}', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Order not found', response.data)
        
# TC-033: Verify a logged out user cannot access profile or order history pages
    def test_logged_out_user_cannot_access_profile_or_orders(self):
        """Test that a logged-out user cannot access profile or order history pages"""
        # Ensure user is logged out
        with self.app as client:
            with client.session_transaction() as sess:
                if 'user_email' in sess:
                    sess.pop('user_email')
        
        # Test profile page access
        response = self.app.get('/account', follow_redirects=True) 
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Please log in to access this page', response.data)
        self.assertIn(b'Login', response.data)  # Verify we're on login page
        
        # Test order history page access 
        response = self.app.get('/order-confirmation/any', follow_redirects=True)  
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Order not found', response.data)  
        
        # Verify session remains empty
        with self.app as client:
            with client.session_transaction() as sess:
                self.assertNotIn('user_email', sess)

# TC-034: Verify a logged in user cannot update another user's profile
    def test_user_cannot_update_others_profile(self):
        """Test that a user cannot update another user's profile"""
        # Create two users
        user1_password = "demo1234"
        user2_password = "demo1235"
        user1 = User("demo@bookstore1.com", user1_password, "Demo User Uno", "1234 Demo Street, Demo City, DC 12345")
        user2 = User("demo@bookstore2.com", user2_password, "Demo User Dos", "1235 Demo Street, Demo City, DC 12345")
        users[user1.email] = user1
        users[user2.email] = user2
        # Log in as user2
        self.app.post('/login', 
                      data={'email': user2.email, 'password': user2_password}, 
                      follow_redirects=True)
        # Attempt to update user1's profile by manipulating form data
        updated_info = {
            'name': 'Hacked Name',
            'address': 'Hacked Address'
        }  
        response = self.app.post('/update-profile', 
                                 data=updated_info, 
                                 follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Profile updated successfully', response.data)
        # Verify user1's information was not changed
        self.assertEqual(user1.name, "Demo User Uno")
        self.assertEqual(user1.address, "1234 Demo Street, Demo City, DC 12345")
        
# TC-035: Verify layout responsiveness (basic check)
    def test_layout_responsiveness(self):
        """Basic check for layout responsiveness by simulating different screen widths"""
        screen_widths = [320, 768, 1024, 1440]  # Mobile, Tablet, Desktop, Large Desktop
        for width in screen_widths:
            resp = self.app.get('/', headers={'User-Agent': f'Mozilla/5.0 (width={width})'})
            self.assertEqual(resp.status_code, 200)
            # Check that the main container div is present
            self.assertIn(b'<div class="container">', resp.data)

# --------------------- Performance Tests --------------------

# TC:036: Verify homepage loads under 500ms
    def test_performance_homepage_load(self):
        """Test that the homepage loads in under 500ms"""
        start_time = perf_counter()
        resp = self.app.get('/')
        end_time = perf_counter()
        duration_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        print(f"Homepage load took {duration_ms:.2f}ms")
        self.assertEqual(resp.status_code, 200)
        self.assertLess(duration_ms, 500, f"Homepage load took too long: {duration_ms:.2f}ms")


# TC-037: Verify that adding to cart is performant (under 200ms)
    def test_performance_add_to_cart(self):
        """Test that adding a book to the cart is performant (under 200ms)"""
        book = BOOKS[0]
        start_time = perf_counter()
        cart.add_book(book, quantity=1)
        end_time = perf_counter()
        duration_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        print(f"Add to cart took {duration_ms:.2f}ms")
        self.assertLess(duration_ms, 200, f"Add to cart took too long: {duration_ms:.2f}ms")

# TC-038: Verify that checkout process is performant (under 1000ms)
# The mocking here might make this redundant a little...
    @patch('app.PaymentGateway.process_payment')
    @patch('app.EmailService.send_order_confirmation')
    @patch('app.get_current_user')
    def test_performance_checkout_process(self, mock_get_current_user, mock_send_email, mock_payment):
        """Test that the checkout process is performant (under 1000ms)"""
        # Setup mock user
        mock_user = MagicMock()
        mock_user.email = 'demo@bookstore.com'
        mock_get_current_user.return_value = mock_user
        # Setup mock payment success
        mock_payment.return_value = {
            'success': True,
            'message': 'Payment processed successfully',
            'transaction_id': 'TEST123'
        }
        # Setup mock email service
        mock_send_email.return_value = True
        # Add item to cart
        book = BOOKS[0]
        cart.add_book(book, quantity=1)
        # Simulate checkout form data
        checkout_data = {
            'name': 'Demo User',
            'email': 'demo@bookstore.com',
            'address': '123 Demo St',
            'city': 'Demoville',
            'zip_code': '12345',
            'payment_method': 'credit_card',
            'card_number': '4111 1111 1111 1234',
            'expiry_date': '12/30',
            'cvv': '123'
        }
        start_time = perf_counter()
        resp = self.app.post('/process-checkout', data=checkout_data, follow_redirects=True)
        end_time = perf_counter()
        duration_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        print(f"Checkout process took {duration_ms:.2f}ms")
        self.assertEqual(resp.status_code, 200)
        self.assertLess(duration_ms, 1000, f"Checkout process took too long: {duration_ms:.2f}ms")

# --------------------- Endpoint Speed Tests --------------------

# TC-039: Test Cart total calculation speed with cProfile
    def test_cart_total_calculation_speed(self):
        """Test the speed of cart total calculation using cProfile and timeit"""
        try:
            # Add multiple items to cart
            for book in BOOKS:
                cart.add_book(book, quantity=5000)

            # Timeit benchmarking
            setup_code = 'from app import cart'
            test_code = "cart.get_total_price()"
            
            # Run timeit benchmark
            exec_time = timeit.timeit(test_code, setup=setup_code, number=2500)
            print(f"\nTimeit Results:")
            print(f"Average time over 10000 runs: {exec_time/1000:.6f} seconds")

            # cProfile benchmarking
            pr = cProfile.Profile()
            pr.enable()
            cart.get_total_price()
            pr.disable()

            # Create string buffer and stats object
            s = io.StringIO()
            ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
            
            # Print stats to buffer
            print("\ncProfile Results:")
            ps.print_stats()
            print(s.getvalue())

            # Performance assertions
            self.assertLess(exec_time/1000, 0.010, 
                "Cart total calculation took more than 10ms on average")

        finally:
            # Clear cart after test
            cart.clear()

# TC-040: Test Book listing retrieval speed with cProfile
    def test_book_listing_retrieval_speed(self):
        """Test the speed of book listing retrieval using cProfile and timeit"""
        try:
            # Timeit benchmarking
            setup_code = 'from app import BOOKS'
            test_code = "len(BOOKS)"
            
            # Run timeit benchmark
            exec_time = timeit.timeit(test_code, setup=setup_code, number=10000)
            print(f"\nTimeit Results:")
            print(f"Average time over 10000 runs: {exec_time/10000:.6f} seconds")

            # cProfile benchmarking
            pr = cProfile.Profile()
            pr.enable()
            _ = len(BOOKS)
            pr.disable()

            # Create string buffer and stats object
            s = io.StringIO()
            ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
            
            # Print stats to buffer
            print("\ncProfile Results:")
            ps.print_stats()
            print(s.getvalue())

            # Performance assertions
            self.assertLess(exec_time/10000, 0.0001, 
                "Book listing retrieval took more than 0.1ms on average")

        finally:
            pass  # No cleanup needed

# This test may not work as I intended it to.
# TC-41: Test User login speed with cProfile using the endpoint
    def test_user_login_speed(self):
        """Test the speed of user login using cProfile and timeit"""
        # Ensure the demo user exists
        demo_email = "demo@bookstore.com"
        demo_password = "demo123"
        self.assertIn(demo_email, users)
        
        # Timeit benchmarking - using a simpler approach
        # Create a reusable test client reference
        client = self.app
        login_data = {'email': demo_email, 'password': demo_password}
        
        # Warm-up run
        client.post('/login', data=login_data, follow_redirects=True)
        
        # Run timeit benchmark with fewer iterations for reasonable test time
        exec_time = timeit.timeit(
            lambda: client.post('/login', data=login_data, follow_redirects=True),
            number=50
        )
        print(f"\nTimeit Results:")
        print(f"Average time over 50 runs: {exec_time/50:.6f} seconds for Login")
        
        # cProfile benchmarking
        pr = cProfile.Profile()
        pr.enable()
        client.post('/login', data=login_data, follow_redirects=True)
        pr.disable()
        
        # Create string buffer and stats object
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
        
        # Print stats to buffer
        print("\ncProfile Results:")
        ps.print_stats(10)  # Limit to top 10 results
        print(s.getvalue())
        
        # Performance assertions - relaxed threshold for testing environment
        avg_time = exec_time / 50
        print(f"Average login time: {avg_time:.6f} seconds")
        self.assertLess(avg_time, 0.5, f"User login took more than 500ms on average: {avg_time:.6f}s")
        

# --------------------- Security Tests --------------------
# TC-042: Verify that SQL Injection attempts are mitigated in login
    def test_sql_injection_login(self):
        """Test that SQL Injection attempts are mitigated in login"""
        sql_injection_payload = "' OR '1'='1"
        response = self.app.post('/login', 
                               data={'email': sql_injection_payload, 'password': sql_injection_payload}, 
                               follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid email or password', response.data)
        # Verify no user is logged in
        with self.app as c:
            with c.session_transaction() as sess:
                self.assertNotIn('user_email', sess)

# TC-043: Verify that XSS attempts are mitigated in user inputs
    def test_xss_mitigation_in_user_inputs(self):
        """Test that XSS attempts are mitigated in user inputs"""
        xss_payload = "<script>alert('XSS')</script>"
        response = self.app.post('/register', 
                            data={
                                'email': 'test@xss.com',
                                'password': 'demo1235',
                                'name': xss_payload,
                                'address': '123 Test St'
                            },
                            follow_redirects=True)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Account created successfully', response.data)
        
        # Get the created user
        created_user = users['test@xss.com']
        
        # Verify the XSS payload was escaped
        self.assertNotIn('<script>', created_user.name)
        self.assertNotIn('</script>', created_user.name)
        self.assertNotIn("alert('XSS')", created_user.name)
        
        # Verify the basic HTML entities are present
        self.assertIn('&lt;', created_user.name)
        self.assertIn('&gt;', created_user.name)

# TC-044: Verify Secure session cookies are set
    def test_secure_session_cookies(self):
        """Test that secure session cookies are set"""
        with self.app as c:
            # Perform a login to set session cookie
            response = c.post('/login', 
                    data={'email': 'demo@bookstore.com', 'password': 'demo123'}, 
                    follow_redirects=True)
            
            # Get the Set-Cookie header from the response
            cookie_header = response.headers.get('Set-Cookie', '')
            
            # Check if we're in a test environment
            if not app.testing:
                # Production environment checks
                self.assertIn('Secure', cookie_header, "Session cookie is not marked as Secure")
            
            # These should be present in all environments
            self.assertIn('HttpOnly', cookie_header, "Session cookie is not marked as HttpOnly")
            self.assertIn('Path=/', cookie_header, "Session cookie does not have Path set")
            
            # Verify session was created
            with c.session_transaction() as sess:
                self.assertIn('user_email', sess, "Session was not created")
                self.assertEqual(sess['user_email'], 'demo@bookstore.com')

# TC-045: Verify passwords are stored as hashes, not plaintext
    def test_password_hashing(self):
        """Test that passwords are hashed and not stored in plaintext"""
        # Create a new user with a known password
        test_password = 'testPassword123!'
        test_user = User('hash@test.com', test_password, 'Hash Test User', '123 Hash St')
        users['hash@test.com'] = test_user
        
        # Verify password is not stored in plaintext
        self.assertNotEqual(test_user.password_hash, test_password)
        
        # Verify password cannot be accessed directly
        with self.assertRaises(AttributeError):
            _ = test_user.password
        
        # Verify password can be checked correctly
        self.assertTrue(test_user.check_password(test_password))
        self.assertFalse(test_user.check_password('wrongPassword'))
        
        # Verify password can be updated
        new_password = 'newPassword456!'
        test_user.set_password(new_password)
        self.assertTrue(test_user.check_password(new_password))
        self.assertFalse(test_user.check_password(test_password))
        
        # Verify password hash changes when password is updated
        old_hash = test_user.password_hash
        test_user.set_password('anotherPassword789!')
        self.assertNotEqual(test_user.password_hash, old_hash)

if __name__ == '__main__':
    unittest.main() 