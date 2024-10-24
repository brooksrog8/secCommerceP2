# Author: brooks and xih
# design based off of http://chrisdianamedia.com/simplestore/
import os.path
import tornado.ioloop
import tornado.web
from tornado.options import define, options
import tornado.template
import MySQLdb
import uuid
import urllib
import re
import magic
import hashlib
import mysql.connector
import bcrypt
import datetime
from datetime import timedelta
# define values for mysql connection
define("port", default=8892, help="run on the given port", type=int)
define("mysql_host", default="127.0.0.1", help="database host")
define("mysql_port", default=3306, help="database port", type=int)
define("mysql_database", default="group5", help="database name")
define("mysql_user", default="group5", help="database user")
define("mysql_password", default="CxdDldXEsm2v6Z788bIDLVj5pf6LXe7L", help="database password")
           

__UPLOADS__ = "static/uploads/"

# hello
class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/login", LoginHandler),
            (r"/logout", LogoutHandler),
            (r"/account", AccountHandler),
            (r"/details/([^/]+)", DetailsHandler),
            (r"/cart", CartHandler),
            (r"/product/add", AddToCartHandler),
            (r"/product/remove/([^/]+)", RemoveFromCartHandler),
            (r"/cart/empty", EmptyCartHandler),
            (r"/upload", UploadHandler),
            (r"/userform", UserformHandler),
            (r"/welcome/([^/]+)", WelcomeHandler),
            (r"/directory/([^/]+)", DirectoryTraversalHandler),
            (r"/signup", SignupHandler)

        ]
        settings = dict(
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            ui_modules={"Small": SmallModule},
            xsrf_cookies=False,
            debug=True,
            cookie_secret="2Xs2dc.y2wqZVB,qRrnyoZuWbUTnjRBG4&uxaMYtM&r%KnpL7e"
        )
        super(Application, self).__init__(handlers, **settings)
        # Have one global connection to the store DB across all handlers
        self.myDB = MySQLdb.connect(host=options.mysql_host,
                                    port=options.mysql_port,
                                    db=options.mysql_database,
                                    user=options.mysql_user,
                                    passwd=options.mysql_password)


class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.myDB

    # if there is no cookie for the current user generate one
    def get_current_user(self):
        if not self.get_cookie("webstore_cookie"):
            self.set_cookie("webstore_cookie", str(uuid.uuid4())),


class HomeHandler(BaseHandler):
    def get(self):
        # get all products in the database for the store's main page
        temp = []
        c = self.db.cursor()
        c.execute("SELECT * FROM products")
        products = c.fetchall()
        # add urlencoded string to tuple for product image link
        for k, v in enumerate(products):
            temp.append(products[k] + (urllib.parse.quote_plus(products[k][2]),))

        authorized = self.get_cookie("loggedin")
        self.render("home.html", products=tuple(temp), auth=authorized)


class DetailsHandler(BaseHandler):
    def get(self, slug):
        # get the selected product from the database
        temp = []
        # remove non numerical characters from slug
        item_number = re.findall(r'\d+', slug)
        c = self.db.cursor()
        c.execute("SELECT * \
                   FROM products p \
                   LEFT JOIN (SELECT `option`, \
                                     GROUP_CONCAT(`value`) AS `value`, \
                                     product_id \
                         FROM `product_options` \
                         WHERE `product_id` = " + item_number[0] + " \
                         GROUP BY `option`) AS o ON o.product_id = p.id \
                   WHERE p.id = " + item_number[0])
        product = c.fetchall()
        # add urlencoded string to tuple for product image link
        quoted_url = urllib.parse.quote_plus(urllib.parse.quote_plus(product[0][2]))
        temp.append(product[0] + (quoted_url,))

        authorized = self.get_cookie("loggedin")
        self.render("details.html",
                    product=tuple(temp),
                    sku=slug,
                    auth=authorized)


class CartHandler(BaseHandler):
    def get(self):
        # get the current user's cookie
        cookie = self.get_cookie("webstore_cookie")
        # get the current user's cart based on their cookie
        c = self.db.cursor()
        query = """SELECT c.item, \
                          p.price, \
                          p.name, \
                          COUNT(*) AS quantity, \
                          SUM(p.price) AS subtotal, \
                          `options`, \
                          GROUP_CONCAT(c.id) AS `id` \
                   FROM cart c \
                   INNER JOIN products p on p.id = c.item \
                   WHERE c.user_cookie = %s \
                   GROUP BY c.item, c.options
                   """
        c.execute(query, (cookie,))
        products = c.fetchall()
        # calculate total and tax values for cart
        total = float(sum([x[4] for x in products]))
        count = sum([x[3] for x in products])
        tax = float("{0:.2f}".format(total * 0.08517))
        shipping = 5.27

        if not total:
            shipping = 0.00

        authorized = self.get_cookie("loggedin")
        self.render("cart.html",
                    products=products,
                    total=total,
                    count=count,
                    shipping=shipping,
                    tax=tax,
                    auth=authorized)


class AddToCartHandler(BaseHandler):
    def post(self):
        # get the product information from the details page
        id = self.get_argument("product", None)
        cookie = self.get_cookie("webstore_cookie")
        product_options = ",".join(self.get_arguments("option"))
        # add the product to the user's cart
        c = self.db.cursor()
        c.execute("INSERT INTO cart (id, user_cookie, item, options) \
                   VALUES (0, '"+cookie+"', "+id+", '"+product_options+"')")
        self.application.myDB.commit()
        self.redirect("/cart")


class RemoveFromCartHandler(BaseHandler):
    def get(self, slug):
        # get the current user's cookie
        cookie = self.get_cookie("webstore_cookie")
        # use that cookie to remove selected item from the user's cart
        c = self.db.cursor()
        query = "DELETE FROM cart \
                   WHERE user_cookie = %s \
                       AND id IN(%s)"
        c.execute(query, (cookie, slug))
        self.application.myDB.commit()
        self.redirect("/cart")


class EmptyCartHandler(BaseHandler):
    def get(self):
        # get the current user's cookie
        cookie = self.get_cookie("webstore_cookie")
        # use that cookie to remove all items from user's cart
        c = self.db.cursor()
        query = "DELETE FROM cart WHERE user_cookie = %s"
        c.execute(query, (cookie,))
        self.application.myDB.commit()
        self.redirect("/cart")


class WelcomeHandler(BaseHandler):
    def get(self, name):
        
        if not re.match(r"^[a-zA-Z]+$", name):
            self.set_status(400)
            self.write("Only letters allowed")
            return
        
        safe_name = tornado.escape.xhtml_escape(name)
        TEMPLATE = open("templates/welcome.html").read()
        template_data = TEMPLATE.replace("FOO", safe_name)
        t = tornado.template.Template(template_data)
        self.write(t.generate(name=safe_name))

class UserformHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("fileuploadform.html")


class UploadHandler(tornado.web.RequestHandler):
    def post(self):
        fileinfo = self.request.files['filearg'][0]
        fname = fileinfo['filename']
        # extn = os.path.splitext(fname)[1]
        # cname = str(uuid.uuid4()) + extn
        fh = open(__UPLOADS__ + fname, 'w')
        fh.write(fileinfo['body'])
        self.finish(fname + " is uploaded!! Check %s folder" % __UPLOADS__)
        # self.write(fileinfo)


class DirectoryTraversalHandler(BaseHandler):
    def get(self, slug):

        # defining allowed directories to 
        # prevent navigating to source code without disrupting
        # availability to view the picture
        allowed_directories = ["static/images", "static/uploads"] 
        base_directory = os.path.abspath(os.path.dirname(__file__)) # base path for server 

        decoded_slug = urllib.parse.unquote(urllib.parse.unquote(slug))  
        requested_file = os.path.normpath(os.path.join(base_directory, decoded_slug))
        requested_file = os.path.abspath(requested_file)  
        
        # checking if requested file is within the set allowed directories
        is_allowed = any(
            requested_file.startswith(os.path.join(base_directory, allowed_dir))
            for allowed_dir in allowed_directories
        )

        if not is_allowed:
            self.set_status(403)
            self.write("Forbidden: Unauthorized file access.")
            return

        if os.path.exists(requested_file) and os.path.isfile(requested_file):
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(requested_file)
            self.set_header('Content-Type', mime_type)
            with open(requested_file, 'rb') as f:
                self.write(f.read())
        else:
            self.set_status(404)
            self.write("File not found")


class SmallModule(tornado.web.UIModule):
    def render(self, item):
        return self.render_string("modules/small.html", item=item)

class SignupHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        name = self.get_body_argument("name", "")
        phone = self.get_body_argument("phone", "")
        email = self.get_body_argument("email", "")
        password = self.get_body_argument("password", "")
        password_confirm = self.get_body_argument("password_confirm", "")

        if password != password_confirm:
            self.write("Passwords do not match.")
            return

        if not self.is_valid_email(email):
            self.write("Invalid email format.")
            return

        # Generate a salt and hash the password with bcrypt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Insert user data into the database
        if self.insert_user(name, phone, email, hashed_password, salt):
            self.redirect("/login")
        else:
            self.write("Failed to create user account or email already exists.")

    def is_valid_email(self, email):
        email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        return re.match(email_regex, email)



    def insert_user(self, name, phone, email, hashed_password, salt):
        try:
            conn = mysql.connector.connect(
                host=options.mysql_host,
                user=options.mysql_user,
                passwd=options.mysql_password,
                database=options.mysql_database
            )
            cursor = conn.cursor()
            query = """
                INSERT INTO users (name, phone, email, hashed_password, salt)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (name, phone, email, hashed_password, salt))
            conn.commit()
        except mysql.connector.Error as err:
            print("Failed inserting user:", err)
            return False
        finally:
            cursor.close()
            conn.close()
        return True

class LoginHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        email = self.get_body_argument("email", "")
        password = self.get_body_argument("password", "")

        # Query the database to retrieve the user's hashed password, failed attempts, and lockout time
        conn = mysql.connector.connect(
            host=options.mysql_host,
            user=options.mysql_user,
            passwd=options.mysql_password,
            database=options.mysql_database
        )
        cursor = conn.cursor()

        try:
            query = "SELECT hashed_password, failed_attempts, lockout_time FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()

            if result:
                hashed_password, failed_attempts, lockout_time = result

                # checking if account is currently locked
                if lockout_time is not None and datetime.datetime.now() < lockout_time:
                    self.write(f"Account is locked. Try again after {lockout_time}.")
                    return

                # check if the hashed input password matches the DB hashed password
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                    # Reset failed attempts on successful login
                    cursor.execute("UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE email = %s", (email,))
                    conn.commit()

                    # setting a cookie to indicate the user is logged in
                    self.set_cookie("loggedin", "true", httponly=True, secure=True, samesite="Lax")
                    self.set_cookie("email", email, httponly=True, secure=True)
                    self.redirect("/account")

                else:
                    # increment failed_attempts if wrong password
                    failed_attempts += 1

                    if failed_attempts >= 5:
                        # lock account for 15 minutes
                        lockout_time = datetime.datetime.now() + timedelta(minutes=15)
                        cursor.execute("UPDATE users SET failed_attempts = %s, lockout_time = %s WHERE email = %s",
                                       (failed_attempts, lockout_time, email))
                        self.write("Too many failed login attempts. Your account has been locked for 15 minutes.")
                    else:
                        cursor.execute("UPDATE users SET failed_attempts = %s WHERE email = %s", (failed_attempts, email))
                        self.write(f"Invalid password. {5 - failed_attempts} attempts remaining.")

                    conn.commit()
            else:
                # No user found with that email, redirect back to login page
                self.redirect("/login")
        except mysql.connector.Error as err:
            print("Error:", err)
            self.write("Database error occurred.")
        finally:
            cursor.close()
            conn.close()

class AccountHandler(BaseHandler):
    def get(self):
        # Ensure the user is logged in
        if not self.get_cookie("loggedin"):
            self.redirect("/login")
            return

        # Fetch user details from the database based on their session or cookie
        user_email = self.get_cookie("email")  # You might store email in the cookie upon login
        if not user_email:
            self.redirect("/login")
            return

        conn = mysql.connector.connect(
            host=options.mysql_host,
            user=options.mysql_user,
            passwd=options.mysql_password,
            database=options.mysql_database
        )
        cursor = conn.cursor()

        try:
            query = "SELECT name, email, phone FROM users WHERE email = %s"
            cursor.execute(query, (user_email,))
            user_data = cursor.fetchone()

            if user_data:
                user_info = {
                    "name": user_data[0],
                    "email": user_data[1],
                    "phone": user_data[2],
                }
                self.render("account.html", user=user_info)
            else:
                print("User not found or not logged in")
                self.redirect("/login")
        finally:
            cursor.close()
            conn.close()


class LogoutHandler(BaseHandler):
    def get(self):
        # Clear the "loggedin" flag and email cookie
        self.clear_cookie("loggedin")
        self.clear_cookie("email")
        
        # Redirect the user to the home page after logout
        self.redirect("/")



def main():
    http_server = tornado.httpserver.HTTPServer(Application(), ssl_options={
    "certfile": os.path.join("certs/host.cert"), "keyfile":
    os.path.join("certs/host.key"), })
    http_server.listen(options.port)
    print(f"Web server started. In your browser, go to http://10.20.0.226:{options.port}")
    tornado.ioloop.IOLoop.current().start()
if __name__ == "__main__":
    main()

