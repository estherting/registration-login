from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
# import the function connectToMySQL from the file mysqlconnection.py
from mysqlconnection import connectToMySQL
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key="SECRET!"
# invoke the connectToMySQL function and pass it the name of the database we're using
# connectToMySQL returns an instance of MySQLConnection, which we will store in the variable 'mysql'
mysql = connectToMySQL('walldb')
# now, we may invoke the query_db method
print("all the users", mysql.query_db("SELECT * FROM users;"))


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register')
def register():
    return render_template('register.html')


@app.route('/process_register', methods=["POST"])
def process_register():
    # store user info in session
    session['temp_first_name'] = request.form['first_name']
    session['temp_last_name'] = request.form['last_name']
    session['temp_email'] = request.form['email']
    session['temp_password'] = request.form['password']
    session['temp_confirm_pw'] = request.form['confirm_pw']

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

    print("*"*300, session)
    if not ('_flashes' in session):
        # encrypt password
        hash = bcrypt.generate_password_hash(password)
        session['hash'] = hash
        query = 'insert into users (first_name, last_name, email, password, created_at, updated_at) values (%(fName)s, %(lName)s, %(e)s, %(pw)s, now(), now())'
        data = {
                'fName': first_name,
                'lName': last_name,
                'e': email,
                'pw': hash
        }
        mysql.query_db(query, data)

        print("all the users", mysql.query_db("SELECT * FROM users;"))
        return redirect('/success')
    return redirect('/register')


@app.route('/process_login', methods=["POST"])
def process_login():
    query = "select * from users where users.email = %(email)s;"
    data = {
            'email': request.form['email']
    }
    result = mysql.query_db(query, data)
    print (result)
    if result:
        query = "select password from users where email = %(email)s;"
        data = {
                'email': request.form['email']
        }
        pw = mysql.query_db(query, data)
        print(pw)
        if bcrypt.check_password_hash(pw[0]['password'], request.form['password']):
            query = "select first_name from users where email = %(email)s;"
            data = {
                    'email': request.form['email']
            }
            result = mysql.query_db(query, data)
            session['email'] = request.form['email']
            session['first_name'] = result[0]['first_name']
            return redirect('/wall')
    else:
        flash("You could not be logged in")
    return redirect('/')


@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/wall')
def wall():
    query = "select users.id, messages.id, messages.message, concat_ws(' ', users.first_name, users.last_name), messages.updated_at from messages join users on messages.users_id = users.id"
    message_data = mysql.query_db(query)
    session['message_data'] = message_data

    query = "select comments.messages_id, concat_ws(' ', users.first_name, users.last_name), comments.updated_at, comments.comment from comments join users on comments.users_id = users.id join messages on comments.users_id = messages.id"
    comment_data = mysql.query_db(query)
    flash(comment_data)
    return render_template('wall.html', comment_data=comment_data)


@app.route('/post_message', methods=['POST'])
def post_message():
    query = "select id from users where email = %(email)s"
    data = {
            'email': session['email']
    }
    user_id = mysql.query_db(query, data)[0]['id']
    if request.form['message']:
        message = request.form['message']
    query = "insert into messages (users_id, message, created_at, updated_at) values (%(user_id)s, %(message)s, now(), now())"
    data = {
            'user_id': user_id,
            'message': request.form['message']
    }
    mysql.query_db(query, data)

    # return message to wall html
    return redirect('/wall')


@app.route('/post_comment', methods=['POST'])
def post_comment():
    # save comment in database
    # find out the user id of the logged-in user
    query = "select id from users where email = %(email)s"
    data = {
            'email': session['email']
    }
    user_id = mysql.query_db(query, data)[0]['id']
    query = "insert into comments (messages_id, users_id, comment, created_at, updated_at) values (%(message_id)s, %(user_id)s, %(comment)s, now(), now())"
    data = {
            'message_id': request.form['message_id'],
            'user_id': user_id,
            'comment': request.form['comment']
    }
    result = mysql.query_db(query, data)
    flash(result)
    # return message to wall html
    return redirect('/wall')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have successfully logged out. Goodbye!")
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
