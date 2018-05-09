from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
# import the function connectToMySQL from the file mysqlconnection.py
from mysqlconnection import connectToMySQL
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key="SECRET!"
# invoke the connectToMySQL function and pass it the name of the database we're using
# connectToMySQL returns an instance of MySQLConnection, which we will store in the variable 'mysql'
mysql = connectToMySQL('loginregistrationdb')
# now, we may invoke the query_db method
print("all the users", mysql.query_db("SELECT * FROM users;"))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/process_register', methods=["POST"])
def process_register():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    session['first_name'] = first_name
    valid_email = False
    if len(first_name) > 0 and not first_name.isalpha():
        flash("First name must contain letters only")
    if len(last_name) > 0 and not last_name.isalpha():
        flash("Last name must contain letters only")
    if len(first_name) < 2:
        flash("First name must contain at least 2 characters")
    if len(last_name) < 2:
        flash("Last name must contain at least 2 characters")

    query = 'select * from users where email = %(entered_email)s'
    data = {
            'entered_email': email
    }
    if mysql.query_db(query, data):
        flash("Email is already registered")

    for c in email:
        if c == "@":
            valid_email = True
    if not valid_email:
        flash("Email must be a valid email")

    if len(password) < 8:
        flash("Password must contain at least 8 characters")

    if password != request.form['confirm_pw']:
        flash("Entered passwords do not match")


    if not ('flashes' in session):
        # encrypt password
        hash = bcrypt.generate_password_hash(password)
        session['hash'] = hash
        query = 'insert into users (first_name, last_name, email, pw_hash) values (%(fName)s, %(lName)s, %(e)s, %(pw)s)'
        data = {
                'fName': first_name,
                'lName': last_name,
                'e': email,
                'pw': hash
        }
        mysql.query_db(query, data)

        print("all the users", mysql.query_db("SELECT * FROM users;"))
        return redirect('/success')

    return redirect('/')


@app.route('/process_login', methods=["POST"])
def process_login():
    query = "select * from users where users.email = %(email)s;"
    data = {
            'email': request.form['email']
    }
    result = mysql.query_db(query, data)
    print (result)
    if result:
        query = "select pw_hash from users where email = %(email)s;"
        data = {
                'email': request.form['email']
        }
        pw = mysql.query_db(query, data)
        print(pw)
        if bcrypt.check_password_hash(pw[0]['pw_hash'], request.form['password']):
            query = "select first_name from users where email = %(email)s;"
            data = {
                    'email': request.form['email']
            }
            result = mysql.query_db(query, data)
            session['first_name'] = result[0]['first_name']
            return redirect('/success')
        else:
            flash("You could not be logged in")
    return redirect('/')



@app.route('/success')
def success():
    return render_template('success.html')



if __name__ == "__main__":
    app.run(debug=True)
