-- Create user with your chosen password
CREATE USER urbanfood_user IDENTIFIED BY urb123;

select * from products;

-- Configure user's tablespace
ALTER USER urbanfood_user DEFAULT TABLESPACE users;
ALTER USER urbanfood_user TEMPORARY TABLESPACE temp;
ALTER USER urbanfood_user QUOTA UNLIMITED ON users;

-- Grant necessary permissions
GRANT CREATE SESSION TO urbanfood_user;
GRANT RESOURCE TO urbanfood_user;
GRANT CREATE TABLE TO urbanfood_user;
GRANT CREATE VIEW TO urbanfood_user;
GRANT CREATE PROCEDURE TO urbanfood_user;

GRANT SELECT, INSERT ON customers TO urbanfood_user;
GRANT SELECT, INSERT, UPDATE ON products TO urbanfood_user;
GRANT EXECUTE ON place_order TO urbanfood_user;
GRANT SELECT, INSERT ON payments TO urbanfood_user;
GRANT SELECT, INSERT ON deliveries TO urbanfood_user;
GRANT SELECT, INSERT,UPDATE ON suppliers TO urbanfood_user;


-----------------------------------------------------------------------
-------------------- SECURITY ENHANCEMENTS  ---------------------------
-----------------------------------------------------------------------

---- Password policy profile
CREATE PROFILE urbanfood_profile LIMIT
  FAILED_LOGIN_ATTEMPTS 5
  PASSWORD_LIFE_TIME 90
  PASSWORD_REUSE_TIME 365
  PASSWORD_REUSE_MAX 5;
  
-- Admin user (for DB management)
CREATE USER urbanfood_admin IDENTIFIED BY "Admin@1234";
ALTER USER urbanfood_admin DEFAULT TABLESPACE users TEMPORARY TABLESPACE temp;
GRANT urbanfood_admin_role TO urbanfood_admin;
GRANT urbanfood_admin_role TO urbanfood_user;
 
---- Apply to existing users
ALTER USER urbanfood_admin PROFILE urbanfood_profile;
ALTER USER urbanfood_user PROFILE urbanfood_profile;


-- categories table
CREATE TABLE categories (
    category_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    category_name VARCHAR2(100) NOT NULL,
    description VARCHAR2(500)
);

-- customers table
CREATE TABLE customers (
    customer_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name VARCHAR2(100) NOT NULL,
    last_name VARCHAR2(100) NOT NULL,
    email VARCHAR2(200) NOT NULL,
    password VARCHAR2(255) NOT NULL,
    phone VARCHAR2(20),
    address VARCHAR2(500),
    created_at TIMESTAMP DEFAULT SYSTIMESTAMP,
    CONSTRAINT uk_customer_email UNIQUE (email)
);

-- suppliers table
CREATE TABLE suppliers (
    supplier_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name VARCHAR2(100) NOT NULL,
    last_name VARCHAR2(100) NOT NULL,
    email VARCHAR2(200) NOT NULL,
    password VARCHAR2(255) NOT NULL,
    phone VARCHAR2(20),
    address VARCHAR2(500),
    farm_name VARCHAR2(200),
    farm_address VARCHAR2(500),
    created_at TIMESTAMP DEFAULT SYSTIMESTAMP,
    CONSTRAINT uk_supplier_email UNIQUE (email)
);



-- products table
CREATE TABLE products (
    product_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    supplier_id NUMBER NOT NULL,
    category_id NUMBER NOT NULL,
    product_name VARCHAR2(200) NOT NULL,
    description VARCHAR2(4000),
    price NUMBER(10,2) NOT NULL,
    stock_quantity NUMBER DEFAULT 0,
    created_at TIMESTAMP DEFAULT SYSTIMESTAMP,
    CONSTRAINT fk_product_supplier FOREIGN KEY (supplier_id) REFERENCES suppliers(supplier_id),
    CONSTRAINT fk_product_category FOREIGN KEY (category_id) REFERENCES categories(category_id),
    CONSTRAINT chk_product_price CHECK (price > 0)
    
);

ALTER TABLE products ADD image VARCHAR2(255);

-- orders table
CREATE TABLE orders (
    order_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id NUMBER NOT NULL,
    order_date TIMESTAMP DEFAULT SYSTIMESTAMP,
    total_amount NUMBER(10,2),
    status VARCHAR2(50) DEFAULT 'pending',
    CONSTRAINT fk_order_customer FOREIGN KEY (customer_id) REFERENCES customers(customer_id)
);

-- order_products table 
CREATE TABLE order_products (
    order_products_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id NUMBER NOT NULL,
    product_id NUMBER NOT NULL,
    quantity NUMBER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL,
    CONSTRAINT fk_op_order FOREIGN KEY (order_id) REFERENCES orders(order_id),
    CONSTRAINT fk_op_product FOREIGN KEY (product_id) REFERENCES products(product_id)
);

-- payments table
CREATE TABLE payments (
    payment_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id NUMBER NOT NULL,
    payment_method VARCHAR2(50) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    payment_date TIMESTAMP DEFAULT SYSTIMESTAMP,
    status VARCHAR2(50) DEFAULT 'pending',
    CONSTRAINT fk_payment_order FOREIGN KEY (order_id) REFERENCES orders(order_id)
);

-- deliveries table
CREATE TABLE deliveries (
    delivery_id NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    order_id NUMBER NOT NULL,
    delivery_address VARCHAR2(500) NOT NULL,
    expected_delivery_date DATE,
    actual_delivery_date DATE,
    status VARCHAR2(50) DEFAULT 'pending',
    CONSTRAINT fk_delivery_order FOREIGN KEY (order_id) REFERENCES orders(order_id)
);

---------------- INDEXES---------------------------
CREATE INDEX idx_order_date ON orders(order_date);
CREATE INDEX idx_product_supplier ON products(supplier_id);


---------------------------------------------------------------------------------
--------------------- ROW-LEVEL SECURITY POLICY ---------------------------------
---------------------------------------------------------------------------------

-- STEP 1: CREATE POLICY FUNCTION
-- Purpose: Dynamically filters PRODUCTS table rows based on supplier identity
-- Mechanism: Compares product.supplier_id with logged-in user's supplier_id
                ----------------------------------------------------------
                
CREATE OR REPLACE FUNCTION product_access_policy(
    p_schema IN VARCHAR2, 
    p_object IN VARCHAR2
) RETURN VARCHAR2 IS
BEGIN
    -- Returns WHERE clause condition that:
    -- 1. Extracts supplier_id from suppliers table
    -- 2. Matches against current session user (email)
    RETURN 'supplier_id = (SELECT supplier_id FROM suppliers WHERE email = SYS_CONTEXT(''USERENV'', ''SESSION_USER''))';
END;
/

------------------------------------------------------------------------
-- STEP 2: APPLY ROW-LEVEL SECURITY POLICY
-- Target: PRODUCTS table
-- Scope: SELECT, UPDATE, DELETE operations
-- Security: update_check enforces policy during DML operations
------------------------------------------------------------------------
BEGIN
    DBMS_RLS.ADD_POLICY(
        object_schema   => USER,            -- Applies to current schema
        object_name     => 'PRODUCTS',      -- Protected table
        policy_name     => 'SUPPLIER_ACCESS_POLICY',
        policy_function => 'product_access_policy',
        statement_types => 'SELECT,UPDATE,DELETE',
        update_check    => TRUE             -- Validates changes against policy
    );
    
    DBMS_OUTPUT.PUT_LINE('SUCCESS: RLS policy active on PRODUCTS table');
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('ERROR: Policy creation failed - ' || SQLERRM);
        RAISE;
END;
/

------- TRIGGER FOR ORDER TOTAL CALCULATION----------
CREATE OR REPLACE TRIGGER trg_update_order_total
AFTER INSERT OR UPDATE OR DELETE ON order_products
FOR EACH ROW
BEGIN
    IF INSERTING OR UPDATING THEN
        UPDATE orders
        SET total_amount = (
            SELECT SUM(quantity * unit_price)
            FROM order_products
            WHERE order_id = :NEW.order_id
        )
        WHERE order_id = :NEW.order_id;
    ELSIF DELETING THEN
        UPDATE orders
        SET total_amount = (
            SELECT SUM(quantity * unit_price)
            FROM order_products
            WHERE order_id = :OLD.order_id
        )
        WHERE order_id = :OLD.order_id;
    END IF;
END;
/

-- ========================================================================================================
-------------------------------------------------INSERT SAMPLE DATA ----------------------------------------

-- categories
INSERT INTO categories (category_name, description) VALUES ('Fruits', 'Fresh organic fruits');
INSERT INTO categories (category_name, description) VALUES ('Vegetables', 'Locally grown vegetables');
INSERT INTO categories (category_name, description) VALUES ('Dairy Products', 'Fresh dairy products');
INSERT INTO categories (category_name, description) VALUES ('Baked Goods', 'Freshly baked items and pastries');
INSERT INTO categories (category_name, description) VALUES ('Crafts', 'Handmade artisanal products');

-- customers
INSERT INTO customers (first_name, last_name, email, password, phone, address) VALUES ('hasini', 'shey', 'hasini@gmail.com', 'hasi123', '0757006368', 'Makola');
UPDATE customers  SET address= 'No:207/3, Makola' WHERE customer_id=1 ;
INSERT INTO customers (first_name, last_name, email, password, phone, address) VALUES ('sachini', 'anjalika', 'sach@gmail.com', 'sach123', '0701878069', 'No:12/A, Malabe');


-- suppliers
INSERT INTO suppliers (first_name, last_name, email, password, phone, address, farm_name, farm_address) VALUES ('mike', 'johnson', 'mike@farm.com', 'mike123', '078456789', '789 farm rd', 'green valley', '789 farm rd');
INSERT INTO suppliers (first_name, last_name, email, password, phone, address, farm_name, farm_address) VALUES ('john', 'doe', 'john@farm.com', 'john123', '078456789', '789 farm rd', 'green valley', '125 dencil rd');
UPDATE suppliers SET farm_name= 'house of crafts' ,phone='0710626061', address='931 peradeniya rd' WHERE supplier_id = 2;
INSERT INTO suppliers (first_name, last_name, email, password, phone, address, farm_name, farm_address) VALUES ('amal', 'perera', 'amal@farm.com', 'amal123', '0775095154', '511/A Gampola', 'agro Park', '25 church rd');
INSERT INTO suppliers (first_name, last_name, email, password, phone, address, farm_name, farm_address) VALUES ('rasal', 'khema', 'rasal@farm.com', 'rasal123', '0765502247', '97/9, Ragama', 'milkey fresh dairies', '52 Dharmarama Rd');


-- products ---
INSERT INTO products (supplier_id, category_id, product_name, description, price, stock_quantity) VALUES (1, 1, 'Organic Apples', 'fresh organic apples from local orchard', 230.00, 100);
INSERT INTO products (supplier_id, category_id, product_name, description, price, stock_quantity) VALUES (1, 1, 'Fresh Strawberries', 'locally grown organic strawberries', 880.00, 100);
INSERT INTO products (supplier_id, category_id, product_name, description, price, stock_quantity) VALUES (1, 1, 'Fresh Strawberries', 'locally grown organic strawberries', 880.00, 100);
INSERT INTO products (supplier_id, category_id, product_name, description, price, stock_quantity) VALUES (2, 5, 'Coconut Shell Candle', 'Natural aromatic home decor', 420.00, 100);
INSERT INTO products (supplier_id, category_id, product_name, description, price, stock_quantity) VALUES (4, 3, 'Organic Raw Honey', 'Natural aromatic home decor', 420.00, 100);

------------------------------------------------------------------------
------------------ PL/SQL PROCEDURE FOR ORDER PLACEMENT-----------------
------------------------------------------------------------------------

CREATE OR REPLACE PROCEDURE place_order(
    p_customer_id IN NUMBER,
    p_product_id IN NUMBER,
    p_quantity IN NUMBER,
    p_order_id OUT NUMBER
) AS
    v_price DECIMAL(10,2);
    v_stock NUMBER;
BEGIN
    -- =========== check stock
    SELECT stock_quantity INTO v_stock FROM products WHERE product_id = p_product_id;
    
    IF v_stock < p_quantity THEN
        RAISE_APPLICATION_ERROR(-20001, 'insufficient stock available');
    END IF;
    
    -- ========== get price
    SELECT price INTO v_price FROM products WHERE product_id = p_product_id;
    
    -- ========== create order
    INSERT INTO orders (customer_id, total_amount)
    VALUES (p_customer_id, v_price * p_quantity)
    RETURNING order_id INTO p_order_id;
    
    -- ========= add to order_products
    INSERT INTO order_products (order_id, product_id, quantity, unit_price)
    VALUES (p_order_id, p_product_id, p_quantity, v_price);
    
    -- ========== update stock
    UPDATE products 
    SET stock_quantity = stock_quantity - p_quantity
    WHERE product_id = p_product_id;
    
    COMMIT;
EXCEPTION
    WHEN OTHERS THEN
        ROLLBACK;
        RAISE;
END place_order;
/

---------------------------------------------------------------------------------
------------------ PL/SQL SALES REPORT PROCEDURE -------------------------------
---------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE calculate_sales_report(
    p_start_date IN TIMESTAMP,
    p_end_date IN TIMESTAMP,
    p_total_sales OUT NUMBER,
    p_top_product OUT VARCHAR2,
    p_top_quantity OUT NUMBER  -- Added for more detail
) AS
BEGIN
    -- Initialize defaults
    p_total_sales := 0;
    p_top_product := 'No sales in period';
    p_top_quantity := 0;
    
    -- Get total sales (NVL handles NULL)
    SELECT NVL(SUM(total_amount), 0)
    INTO p_total_sales
    FROM orders
    WHERE order_date BETWEEN p_start_date AND p_end_date;
    
    -- Get top product (if any sales exist)
    IF p_total_sales > 0 THEN
        SELECT p.product_name, t.total_quantity
        INTO p_top_product, p_top_quantity
        FROM (
            SELECT op.product_id, SUM(op.quantity) AS total_quantity
            FROM order_products op
            JOIN orders o ON op.order_id = o.order_id
            WHERE o.order_date BETWEEN p_start_date AND p_end_date
            GROUP BY op.product_id
            ORDER BY total_quantity DESC
            FETCH FIRST 1 ROW ONLY
        ) t
        JOIN products p ON t.product_id = p.product_id;
    END IF;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        NULL; -- Use default values set above
    WHEN OTHERS THEN
        RAISE;
END;
/

---------------------------------------------------------------------------------------
-------------------- PL/SQL FUNCTION FOR GET HIGH-DEMAND PRODUCT  ---------------------
---------------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION get_high_demand_products(
    p_threshold IN NUMBER DEFAULT 1
) RETURN SYS_REFCURSOR IS
    v_result SYS_REFCURSOR;
    v_error_msg VARCHAR2(4000);  -- Added variable for error handling
BEGIN
    OPEN v_result FOR
        SELECT p.product_id, 
               p.product_name, 
               SUM(op.quantity) AS total_ordered,
               COUNT(DISTINCT op.order_id) AS order_count
        FROM products p
        JOIN order_products op ON p.product_id = op.product_id
        GROUP BY p.product_id, p.product_name
        HAVING SUM(op.quantity) >= p_threshold
        ORDER BY total_ordered DESC;
    
    RETURN v_result;
EXCEPTION
    WHEN OTHERS THEN
        v_error_msg := 'Error: ' || SQLERRM;  -- Capture error message in PL/SQL
        
        -- Return error message in cursor
        OPEN v_result FOR 
            SELECT 
                NULL AS product_id, 
                v_error_msg AS product_name,  -- Use variable here
                0 AS total_ordered,
                0 AS order_count
            FROM dual
            WHERE 1 = 0;
            
        RETURN v_result;
END;
/

------------------------------------------------------------------------------
--------------- TEST PROCEDURE FOR GET_HIGH_DEMAND_PRODUCTS ------------------

-- Purpose: Verify the function returns products meeting quantity threshold
-- Usage: Displays product name, total units sold, and order count
------------------------------------------------------------------------------
DECLARE
    v_cursor SYS_REFCURSOR;     -- Declare a cursor variable
    v_id NUMBER;                -- Variable to store product ID
    v_name VARCHAR2(200);       -- Variable to store product name
    v_qty NUMBER;               -- Variable to store total ordered quantity
    v_orders NUMBER;            -- Variable to store order count
BEGIN
    DBMS_OUTPUT.PUT_LINE('HIGH-DEMAND PRODUCT REPORT');
    DBMS_OUTPUT.PUT_LINE('-------------------------');
    
    -- Call function with threshold of 5 units
    v_cursor := get_high_demand_products(5);
    
     -- Loop through the cursor results
    LOOP
         -- Fetch data into variables
        FETCH v_cursor INTO v_id, v_name, v_qty, v_orders;
        EXIT WHEN v_cursor%NOTFOUND;
        
        DBMS_OUTPUT.PUT_LINE(v_name || ': ' || v_qty || ' units (' || v_orders || ' orders)');
        
    END LOOP;
    
    CLOSE v_cursor;          -- Clean up
    
    DBMS_OUTPUT.PUT_LINE('-------------------------');
    DBMS_OUTPUT.PUT_LINE('End of report');
    
EXCEPTION
    WHEN OTHERS THEN
        DBMS_OUTPUT.PUT_LINE('Error: ' || SQLERRM);
        IF v_cursor%ISOPEN THEN
            CLOSE v_cursor;
        END IF;
END;
/


------------------------------------------------------------------------
------------ DATABASE SECURITY IMPROVEMENTS (ROLES) --------------------
------------------------------------------------------------------------

--========== Create dedicated roles for each user type ===============--
CREATE ROLE urbanfood_customer_role NOT IDENTIFIED;
CREATE ROLE urbanfood_supplier_role NOT IDENTIFIED;
CREATE ROLE urbanfood_admin_role NOT IDENTIFIED;

--========== Grant privileges to each role ===============--

---------- Customer role (basic access)--------------
GRANT CREATE SESSION TO urbanfood_customer_role;
GRANT SELECT ON customers TO urbanfood_customer_role;
GRANT SELECT ON products TO urbanfood_customer_role;
GRANT SELECT ON categories TO urbanfood_customer_role;
GRANT EXECUTE ON place_order TO urbanfood_customer_role;

---------- Supplier role (manage their own products)-------------------
GRANT CREATE SESSION TO urbanfood_supplier_role;
GRANT SELECT, INSERT, UPDATE ON products TO urbanfood_supplier_role;
GRANT SELECT ON categories TO urbanfood_supplier_role;
GRANT SELECT ON suppliers TO urbanfood_supplier_role;

---------- Admin role (full control)-------------------
GRANT CONNECT, RESOURCE TO urbanfood_admin_role;

GRANT SELECT, INSERT, UPDATE, DELETE ON customers TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON suppliers TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON products TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON categories TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON order_products TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON payments TO urbanfood_admin_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON deliveries TO urbanfood_admin_role;

--  Procedure privileges for Admin user :
GRANT EXECUTE ON place_order TO urbanfood_admin_role;
GRANT EXECUTE ON calculate_sales_report TO urbanfood_admin_role;
GRANT EXECUTE ON get_high_demand_products TO urbanfood_admin_role;



---------------------------------------- SAMPLE QUERIES ------------------------------------------

-- get all products with supplier info
SELECT p.product_name, p.price, s.farm_name AS supplier
 FROM products p JOIN suppliers s ON p.supplier_id = s.supplier_id;

-- get order history for a customer
SELECT o.order_id, o.order_date, o.total_amount, o.status
 FROM orders o WHERE o.customer_id = 1;
 
--------------- VALIDATION BLOCK-----------------
PROMPT ************ VALIDATING SCHEMA ************
SELECT 
    (SELECT COUNT(*) FROM user_tables) AS tables_created,    ---- Total number of tables in schema
    (SELECT COUNT(*) FROM user_indexes) AS indexes_created, ---- Total indexes
    (SELECT COUNT(*) FROM user_policies) AS rls_policies    ---- Confirms the Row-Level Security policy is active
FROM dual;

GRANT SELECT, INSERT, UPDATE, DELETE ON products TO urbanfood_user;
------------------------------------------------------------------------------
--------------------------------- AUDITING -----------------------------------
------------------------------------------------------------------------------

------------------ Track only high-risk admin actions
AUDIT CREATE TABLE, ALTER TABLE, DROP TABLE BY urbanfood_admin BY ACCESS;
AUDIT EXECUTE PROCEDURE BY urbanfood_admin BY ACCESS;

SELECT * FROM products;
SELECT * FROM categories;
SELECT*FROM suppliers;

BEGIN
    DBMS_RLS.DROP_POLICY(
        object_schema   => USER, 
        object_name     => 'PRODUCTS', 
        policy_name     => 'SUPPLIER_ACCESS_POLICY'
    );
END;
/

-- Check effective privileges (run as urbanfood_user):
SELECT * FROM USER_TAB_PRIVS WHERE TABLE_NAME = 'PRODUCTS';

-- Verify RLS impact:
SELECT * FROM USER_POLICIES;
    
SELECT * FROM DBA_POLICIES WHERE OBJECT_NAME = 'PRODUCTS';    
    
---------------------------------------------------------------
-- As ADMIN (should see all rows)
CONNECT urbanfood_admin/Admin@1234;
SELECT COUNT(*) FROM products;  

-- As SUPPLIER (should see only their products)
CONNECT mike@farm.com/mike123;
SELECT COUNT(*) FROM products;  -- Should return only Mike's products

SELECT * FROM products;



SELECT * FROM deliveries ;

INSERT INTO payments (order_id, payment_method, amount, payment_date, status) 
VALUES (1, 'Credit Card', 150.00, SYSTIMESTAMP, 'completed');

INSERT INTO payments (order_id, payment_method, amount, payment_date, status) 
VALUES (2, 'Credit Card', 89.99, SYSTIMESTAMP, 'completed');


INSERT INTO orders (customer_id, total_amount, status) 
VALUES (1, 150.00, 'completed');

INSERT INTO orders (customer_id, total_amount, status) 
VALUES (2, 89.99, 'completed');

INSERT INTO deliveries (order_id, delivery_address, expected_delivery_date, actual_delivery_date, status)
VALUES (1, 'No. 123, Main Street, Colombo', TO_DATE('2025-04-21', 'YYYY-MM-DD'), NULL, 'pending');

INSERT INTO deliveries (order_id, delivery_address, expected_delivery_date, actual_delivery_date, status)
VALUES (2, '456 Kandy Road, Kandy', TO_DATE('2025-04-22', 'YYYY-MM-DD'), TO_DATE('2025-04-22', 'YYYY-MM-DD'), 'delivered');

DELETE FROM customers WHERE customer_id=10;
