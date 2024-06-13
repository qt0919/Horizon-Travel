import mysql.connector, dbfunc
from flask import Flask, render_template, request, session, redirect, url_for, redirect, flash, jsonify
from passlib.hash import sha256_crypt
import hashlib
import gc
from functools import wraps

app = Flask(__name__)
app.secret_key = 'This is my Secret Key'     #secret keey for sessions

@app.route('/')
def index():
	conn = dbfunc.getConnection()
	if conn != None:    #Checking if connection is None         
		print('MySQL Connection is established')                          
		dbcursor = conn.cursor()    #Creating cursor object            
		dbcursor.execute('SELECT DISTINCT deptCity FROM transportation;')   
		#print('SELECT statement executed successfully.')             
		rows = dbcursor.fetchall()                                    
		dbcursor.close()              
		conn.close() #Connection must be 
		cities = []
		for city in rows:
			city = str(city).strip("(")
			city = str(city).strip(")")
			city = str(city).strip(",")
			city = str(city).strip("'")
			cities.append(city)
		return render_template('home.jinja2', departurelist=cities)
	else:
		print('DB connection Error')
		return 'DB Connection Error'

@app.route('/<usertype>')
def mainpage(usertype):
    return render_template('home.jinja2', usertype=usertype)

'''
@app.route("/Signin")
def signin():
    return render_template("Signin.jinja2")
'''
@app.route('/Signin', methods=['POST', 'GET'])
def register():
    error = ''
    print('Register start')
    try:
        if request.method == "POST":         
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']  
            tel = request.form['tel']  
            gender = request.form['gender']                  
            if username != None and password != None and email != None:           
                conn = dbfunc.getConnection()
                if conn != None:    #Checking if connection is None           
                    if conn.is_connected(): #Checking if connection is established
                        print('MySQL Connection is established')                          
                        dbcursor = conn.cursor()    #Creating cursor object 
                        #here we should check if username / email already exists                                                           
                        password = sha256_crypt.hash((str(password)))           
                        Verify_Query = "SELECT * FROM users WHERE username = %s;"
                        dbcursor.execute(Verify_Query,(username,))
                        rows = dbcursor.fetchall()           
                        if dbcursor.rowcount > 0:   #this means there is a user with same name
                            print('username already taken, please choose another')
                            error = "User name already taken, please choose another"
                            return render_template("Signin.jinja2", error=error)    
                        else:   #this means we can add new user             
                            dbcursor.execute("INSERT INTO users (tel, gender, username, password_hash, \
                                 email) VALUES (%s, %s,%s, %s, %s)", (tel, gender, username, password, email))                
                            conn.commit()  #saves data in database              
                            print("Thanks for registering!")
                            dbcursor.close()
                            conn.close()
                            gc.collect()                        
                            session['logged_in'] = True     #session variables
                            session['username'] = username
                            session['usertype'] = 'standard'   #default all users are standard
                            return redirect(url_for('userpage'))
                    else:                        
                        print('Connection error')
                        return 'DB Connection Error'
                else:                    
                    print('Connection error')
                    return 'DB Connection Error'
            else:                
                print('empty parameters')
                return render_template("Signin.jinja2", error=error)
        else:            
            return render_template("Signin.jinja2", error=error)        
    except Exception as e:                
        return render_template("Signin.jinja2", error=e)    
    return render_template("Signin.jinja2", error=error)

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:            
            print("You need to login first")
            #return redirect(url_for('login', error='You need to login first'))
            return render_template('Login.jinja2', error='You need to login first')    
    return wrap


@app.route('/Login', methods=["GET","POST"])
def login():
    form={}
    error = ''
    try:	
        if request.method == "POST":            
            email = request.form['email']
            password = request.form['password']            
            form = request.form
            print('login start 1.1')
            
            if email != None and password != None:  #check if un or pw is none          
                conn = dbfunc.getConnection()
                if conn != None:    #Checking if connection is None                    
                    if conn.is_connected(): #Checking if connection is established                        
                        print('MySQL Connection is established')                          
                        dbcursor = conn.cursor()    #Creating cursor object                                                 
                        dbcursor.execute("SELECT password_hash, usertype, username, idCustomer \
                            FROM users WHERE email = %s;", (email,))                                                
                        data = dbcursor.fetchone()
                        #print(data[0])
                        if dbcursor.rowcount < 1: #this mean no user exists                         
                            error = "User / password does not exist, login again"
                            return render_template("Login.jinja2", error=error)
                        else:                            
                            #data = dbcursor.fetchone()[0] #extracting password   
                            # verify passowrd hash and password received from user                                                             
                            if sha256_crypt.verify(request.form['password'], str(data[0])):                                
                                session['logged_in'] = True     #set session variables
                                session['email'] = request.form['email']
                                session['usertype'] = str(data[1])  
                                session['username'] = str(data[2])
                                session['idCustomer'] = str(data[3])
                                print("You are now logged in")  
                                if (session['usertype'] == 'admin'):                           
                                    return redirect(url_for('adminpage')) 
                                else: 
                                    return redirect(url_for('userpage')) 
                            else:
                                error = "Invalid credentials username/password, try again."                               
                    gc.collect()
                    print('login start 1.10')
                    return render_template("Login.jinja2", form=form, error=error)
    except Exception as e:                
        error = str(e) + " <br/> Invalid credentials, try again."
        return render_template("Login.jinja2", form=form, error = error)   
    
    return render_template("Login.jinja2", form=form, error = error)

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if ('logged_in' in session) and (session['usertype'] == 'admin'):
            return f(*args, **kwargs)
        else:            
            print("You need to login first as admin user")
            #return redirect(url_for('login', error='You need to login first as admin user'))
            return render_template('Login.jinja2', error='You need to login first as admin user')    
    return wrap

#We also write a wrapper for standard user(s). It will check with the usertype is 
#standard and user is logged in, only then it will allow user to perform standard user functions
def standard_user_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if ('logged_in' in session) and (session['usertype'] == 'standard'):
            return f(*args, **kwargs)
        else:            
            print("You need to login first as standard user")
            #return redirect(url_for('login', error='You need to login first as standard user'))
            return render_template('Login.jinja2', error='You need to login first as standard user')    
    return wrap

@app.route("/logout/")
@login_required
def logout():    
    session.clear()    #clears session variables
    print("You have been logged out!")
    gc.collect()
    #return render_template("home.jinja2", optionalmessage='You have been logged out')
    return redirect(url_for('index')) 
     
@app.route('/admin')
@login_required
@admin_required
def adminpage():
    return render_template('useraccount.html', \
                                     data='this is user specific data',\
                                         usertype=session['usertype'], username=session['username'])

@app.route('/user')
@login_required
@standard_user_required
def userpage():
    return render_template('useraccount.html',username=session['username'], usertype=session['usertype'])


@app.route("/privacy")
def privacy():
    return render_template("privacy.jinja2")

@app.route("/term")
def term():
    return render_template("term.jinja2")

@app.route("/cookies")
def cookies():
    return render_template("cookies.html")



@app.route ('/returncity/', methods = ['POST', 'GET'])
def ajax_returncity():   
	print('/returncity') 

	if request.method == 'GET':
		deptcity = request.args.get('q')
		conn = dbfunc.getConnection()
		if conn != None:    #Checking if connection is None         
			print('MySQL Connection is established')                          
			dbcursor = conn.cursor()    #Creating cursor object            
			dbcursor.execute('SELECT DISTINCT arrivCity FROM transportation WHERE arrivCity = %s;', (deptcity,))   
			#print('SELECT statement executed successfully.')             
			rows = dbcursor.fetchall()
			total = dbcursor.rowcount                                    
			dbcursor.close()              
			conn.close() #Connection must be closed			
			return jsonify(returncities=rows, size=total)
		else:
			print('DB connection Error')
			return jsonify(returncities='DB Connection Error')
                

@app.route ('/selectBooking', methods = ['POST', 'GET'])
def selectBooking():
	if request.method == 'POST':
		#print('Select booking initiated')
		departcity = request.form['departureslist']
		arrivalcity = request.form['arrivalslist']
		date = request.form['date']
		returndate = request.form['returndate']
		nooftickets = request.form['nooftickets']
		lookupdata = [departcity, arrivalcity, date, returndate, nooftickets]
		#print(lookupdata)
		conn = dbfunc.getConnection()
		if conn != None:    #Checking if connection is None         
			print('MySQL Connection is established')                          
			dbcursor = conn.cursor()    #Creating cursor object            
			dbcursor.execute('SELECT * FROM transportation WHERE deptCity = %s AND arrivCity = %s;', (departcity, arrivalcity))   
		#	print('SELECT statement executed successfully.')             
			rows = dbcursor.fetchall()
			datarows=[]			
			for row in rows:
				data = list(row)                    
				fare = (float(row[5]) * float(nooftickets)) 
				#print(fare)
				data.append(fare)
				#print(data)
				datarows.append(data)			
			dbcursor.close()              
			conn.close() #Connection must be closed
			#print(datarows)
			#print(len(datarows))			
			return render_template('booking_start.jinja2', resultset=datarows, lookupdata=lookupdata, username=session['username'], usertype=session['usertype'])
		else:
			print('DB connection Error')
			return redirect(url_for('index'))

	
@app.route ('/booking_confirm/', methods = ['POST', 'GET'])
def booking_confirm():
	if request.method == 'POST':		
		#print('booking confirm initiated')
		journeyid = request.form['bookingchoice']		
		departcity = request.form['deptcity']
		arrivalcity = request.form['arrivcity']
		date = request.form['date']
		returndate = request.form['returndate']
		nooftickets = request.form['nooftickets']
		totalfare = request.form['totalfare']
		cardnumber = request.form['cardnumber']

		totalseats = int(nooftickets)
		bookingdata = [journeyid, departcity, arrivalcity, date, returndate, nooftickets, totalfare]
		#print(bookingdata)
		conn = dbfunc.getConnection()
		if conn != None:    #Checking if connection is None         
			print('MySQL Connection is established')                          
			dbcursor = conn.cursor()    #Creating cursor object     	
			dbcursor.execute('INSERT INTO booking (date_start, date_end, transport_id, noOfseat, totFare, idCustomer) VALUES \
				(%s, %s, %s, %s, %s, %s);', (date, returndate, journeyid, totalseats, totalfare, session['idCustomer']))   
			print('Booking statement executed successfully.')             
			conn.commit()	
			#dbcursor.execute('SELECT AUTO_INCREMENT - 1 FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s;', ('TEST_DB', 'bookings'))   
			dbcursor.execute('SELECT LAST_INSERT_ID();')
			#print('SELECT statement executed successfully.')             
			rows = dbcursor.fetchone()
			#print ('row count: ' + str(dbcursor.rowcount))
			bookingid = rows[0]
			bookingdata.append(bookingid)
			dbcursor.execute('SELECT * FROM transportation WHERE transport_id = %s;', (journeyid,))   			
			rows = dbcursor.fetchall()
			deptTime = rows[0][2]
			arrivTime = rows[0][4]
			bookingdata.append(deptTime)
			bookingdata.append(arrivTime)
			#print(bookingdata)
			#print(len(bookingdata))
			cardnumber = cardnumber[-4:-1]
			print(cardnumber)
			dbcursor.execute
			dbcursor.close()              
			conn.close() #Connection must be closed
			return render_template('booking_confirm.html', resultset=bookingdata, cardnumber=cardnumber,username=session['username'], usertype=session['usertype'])
		else:
			print('DB connection Error')
			return redirect(url_for('index'))

@app.route ('/dumpsVar/', methods = ['POST', 'GET'])
def dumpVar():
	if request.method == 'POST':
		result = request.form
		output = "<H2>Data Received: </H2></br>"
		output += "Number of Data Fields : " + str(len(result))
		for key in list(result.keys()):
			output = output + " </br> " + key + " : " + result.get(key)
		return output
	else:
		result = request.args
		output = "<H2>Data Received: </H2></br>"
		output += "Number of Data Fields : " + str(len(result))
		for key in list(result.keys()):
			output = output + " </br> " + key + " : " + result.get(key)
		return output  

@app.route("/user/booking")
@login_required
@standard_user_required
def booking():
	conn = dbfunc.getConnection()
	if conn != None:    #Checking if connection is None         
		print('MySQL Connection is established')                          
		dbcursor = conn.cursor()    #Creating cursor object            
		dbcursor.execute('SELECT DISTINCT deptCity FROM transportation;')   
		#print('SELECT statement executed successfully.')             
		rows = dbcursor.fetchall()                                    
		dbcursor.close()              
		conn.close() #Connection must be 
		cities = []
		for city in rows:
			city = str(city).strip("(")
			city = str(city).strip(")")
			city = str(city).strip(",")
			city = str(city).strip("'")
			cities.append(city)
        
		return render_template('booking.jinja2', departurelist=cities, username=session['username'], usertype=session['usertype'])
	else:
		print('DB connection Error')
		return 'DB Connection Error'


@app.route('/admin/add')
def show_list():
    #fetch all tutors
    conn = dbfunc.getConnection()
    if conn != None:    #Checking if connection is None
        if conn.is_connected(): #Checking if connection is established
            print('MySQL Connection is established')                          
            dbcursor = conn.cursor()    #Creating cursor object            
            dbcursor.execute('SELECT * FROM transportation;')   
            print('SELECT statement executed successfully.')             
            rows = dbcursor.fetchall()                                    
            dbcursor.close()              
            conn.close() #Connection must be closed
            return render_template('adminadd.jinja2', resultset=rows, usertype=session['usertype'],username=session['username'])
        else:
            print('DB connection Error')
            return 'DB Connection Error'
    else:
        print('DB Connection Error')
        return 'DB Connection Error'

@app.route('/add_transport', methods=['POST', 'GET'])
def add_transport():     
    if request.method == 'GET':
        transportid = request.args.get('transportid')
        departurecity = request.args.get('departurecity')
        time_from = request.args.get('time_from')
        arrivcity = request.args.get('arrivcity')
        time_to = request.args.get('time_to')
        price = request.args.get('price')
        if transportid != None :
            conn = dbfunc.getConnection()
            if conn != None:    #Checking if connection is None
                if conn.is_connected(): #Checking if connection is established
                    print('MySQL Connection is established')                          
                    dbcursor = conn.cursor()    #Creating cursor object            
                    SQL_statement = 'INSERT INTO transportation VALUES (%s, %s, %s, %s, %s, %s);'
                    args = (transportid,departurecity,time_from,arrivcity,time_to,price)
                    dbcursor.execute(SQL_statement,args)
                    print('INSERT statement executed successfully.') 
                    conn.commit()                                
                    dbcursor.close()              
                    conn.close() #Connection must be closed
                    return redirect(url_for('show_list')) 
                else:
                    print('DB connection Error')
                    return 'DB Connection Error'
            else:
                print('DB Connection Error')
                return 'DB Connection Error'
        else:
            print('Invalid tutor id received')
            return render_template('basicdbformexample.html')


@app.route('/admin/update')
def admin_update():
    #fetch all tutors
    conn = dbfunc.getConnection()
    if conn != None:    #Checking if connection is None
        if conn.is_connected(): #Checking if connection is established
            print('MySQL Connection is established')                          
            dbcursor = conn.cursor()    #Creating cursor object            
            dbcursor.execute('SELECT * FROM transportation;')   
            print('SELECT statement executed successfully.')             
            rows = dbcursor.fetchall()                                    
            dbcursor.close()              
            conn.close() #Connection must be closed
            return render_template('adminupdate.jinja2', resultset=rows, usertype=session['usertype'],username=session['username'])
        else:
            print('DB connection Error')
            return 'DB Connection Error'
    else:
        print('DB Connection Error')
        return 'DB Connection Error'

@app.route('/update_transport', methods=['POST', 'GET'])
def update_transport():
    if request.method == 'GET':
        transportid = request.args.get('transportid')
        departurecity = request.args.get('departurecity')
        time_from = request.args.get('time_from')
        arrivcity = request.args.get('arrivcity')
        time_to = request.args.get('time_to')
        price = request.args.get('price')
        if transportid != None:
            conn = dbfunc.getConnection()
            if conn != None:    # Checking if connection is None
                if conn.is_connected(): # Checking if connection is established
                    print('MySQL Connection is established')
                    dbcursor = conn.cursor()    # Creating cursor object
                    SQL_statement = 'UPDATE transportation SET deptCity=%s, time_from=%s, arrivCity=%s, time_to=%s, price=%s WHERE transport_id=%s;'
                    args = (departurecity, time_from, arrivcity, time_to, price, transportid)
                    dbcursor.execute(SQL_statement,args)
                    print('UPDATE statement executed successfully.')
                    conn.commit()
                    dbcursor.close()
                    conn.close() # Connection must be closed
                    return redirect(url_for('admin_update'))
                else:
                    print('DB connection Error')
                    return 'DB Connection Error'
            else:
                print('DB Connection Error')
                return 'DB Connection Error'
        else:
            print('Invalid transport id received')
            return redirect(url_for('admin_update'))

@app.route('/admin/update_user')
def admin_userdetail():
    #fetch all tutors
    conn = dbfunc.getConnection()
    if conn != None:    #Checking if connection is None
        if conn.is_connected(): #Checking if connection is established
            print('MySQL Connection is established')                          
            dbcursor = conn.cursor()    #Creating cursor object            
            dbcursor.execute('SELECT * FROM users;')   
            print('SELECT statement executed successfully.')             
            rows = dbcursor.fetchall()                                    
            dbcursor.close()              
            conn.close() #Connection must be closed
            return render_template('updateuser.jinja2', resultset=rows, usertype=session['usertype'],username=session['username'])
        else:
            print('DB connection Error')
            return 'DB Connection Error'
    else:
        print('DB Connection Error')
        return 'DB Connection Error'

@app.route('/update_user', methods=['POST', 'GET'])
def update_user():
    if request.method == 'GET':
        idCustomer = request.args.get('idCustomer')
        username = request.args.get('username')
        tel = request.args.get('tel')
        email = request.args.get('email')
        gender = request.args.get('gender')
        password = request.args.get('password_hash')
        usertype = request.args.get('usertype')
        if idCustomer != None:
            conn = dbfunc.getConnection()
            if conn != None:    # Checking if connection is None
                if conn.is_connected(): # Checking if connection is established
                    print('MySQL Connection is established')
                    dbcursor = conn.cursor()    # Creating cursor object
                    password = sha256_crypt.hash((str(password))) 
                    SQL_statement = 'UPDATE users SET username=%s, tel=%s, email=%s, gender=%s, password_hash=%s, usertype=%s WHERE idCustomer=%s;'
                    args = (username, tel, email, gender, password, usertype, idCustomer )
                    dbcursor.execute(SQL_statement,args)
                    print('UPDATE statement executed successfully.')
                    conn.commit()
                    dbcursor.close()
                    conn.close() # Connection must be closed
                    return redirect(url_for('admin_userdetail'))
                else:
                    print('DB connection Error')
                    return 'DB Connection Error'
            else:
                print('DB Connection Error')
                return 'DB Connection Error'
        else:
            print('Invalid transport id received')
            return render_template('basicdbformexample.html')
        

@app.route('/admin/add_user')
def admin_adduser():
    #fetch all tutors
    conn = dbfunc.getConnection()
    if conn != None:    #Checking if connection is None
        if conn.is_connected(): #Checking if connection is established
            print('MySQL Connection is established')                          
            dbcursor = conn.cursor()    #Creating cursor object            
            dbcursor.execute('SELECT * FROM users;')   
            print('SELECT statement executed successfully.')             
            rows = dbcursor.fetchall()                                    
            dbcursor.close()              
            conn.close() #Connection must be closed
            return render_template('adduser.jinja2', resultset=rows, usertype=session['usertype'],username=session['username'])
        else:
            print('DB connection Error')
            return 'DB Connection Error'
    else:
        print('DB Connection Error')
        return 'DB Connection Error'

@app.route('/add_user', methods=['POST', 'GET'])
def add_user():
    if request.method == 'GET':
        idCustomer = request.args.get('idCustomer')
        username = request.args.get('username')
        tel = request.args.get('tel')
        email = request.args.get('email')
        gender = request.args.get('gender')
        password = request.args.get('password_hash')
        usertype = request.args.get('usertype')
        if idCustomer != None:
            conn = dbfunc.getConnection()
            if conn != None:    # Checking if connection is None
                if conn.is_connected(): # Checking if connection is established
                    print('MySQL Connection is established')
                    dbcursor = conn.cursor()    # Creating cursor object
                    password = sha256_crypt.hash((str(password))) 
                    SQL_statement = 'INSERT INTO users SET username=%s, tel=%s, email=%s, gender=%s, password_hash=%s, usertype=%s ,idCustomer=%s;'
                    args = (username, tel, email, gender, password, usertype, idCustomer )
                    dbcursor.execute(SQL_statement,args)
                    print('UPDATE statement executed successfully.')
                    conn.commit()
                    dbcursor.close()
                    conn.close() # Connection must be closed
                    return redirect(url_for('admin_adduser'))
                else:
                    print('DB connection Error')
                    return 'DB Connection Error'
            else:
                print('DB Connection Error')
                return 'DB Connection Error'
        else:
            print('Invalid transport id received')
            return render_template('basicdbformexample.html')
        
@app.route('/user/update')
def user_update():
    #fetch all tutors
    conn = dbfunc.getConnection()
    if conn != None:    #Checking if connection is None
        if conn.is_connected(): #Checking if connection is established
            print('MySQL Connection is established')                          
            dbcursor = conn.cursor()    #Creating cursor object 
            idCustomer = session.get("idCustomer")        
            dbcursor.execute('SELECT * FROM users WHERE idCustomer=%s;', (idCustomer,))   
            print('SELECT statement executed successfully.')             
            rows = dbcursor.fetchall()                                    
            dbcursor.close()              
            conn.close() #Connection must be closed
            return render_template('userupdate.jinja2', resultset=rows, usertype=session['usertype'],username=session['username'])
        else:
            print('DB connection Error')
            return 'DB Connection Error'
    else:
        print('DB Connection Error')
        return 'DB Connection Error'

@app.route('/change_password', methods=['POST'])
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        if new_password == confirm_password:
            hashed_password = sha256_crypt.hash(new_password)
            conn = dbfunc.getConnection()
            if conn != None:
                if conn.is_connected():
                    dbcursor = conn.cursor()
                    SQL_statement = 'UPDATE users SET password_hash=%s WHERE idCustomer=%s;'
                    args = (hashed_password, session['idCustomer'])
                    dbcursor.execute(SQL_statement, args)
                    print('Password updated successfully.')
                    conn.commit()
                    dbcursor.close()
                    conn.close()
                    return redirect(url_for('user_update'))
                else:
                    print('DB connection Error')
                    return 'DB Connection Error'
            else:
                print('DB Connection Error')
                return 'DB Connection Error'
        else:
            print('Passwords do not match')
            return 'Passwords do not match'

@app.route('/user/tickets', methods=['GET'])
def tickets():
    # Get the user's bookings from the database
    conn = dbfunc.getConnection()
    if conn is None:
        print('DB connection Error')
        return redirect(url_for('index'))
    dbcursor = conn.cursor()
    dbcursor.execute('SELECT * FROM booking WHERE idCustomer=%s;', (session['idCustomer'],))
    bookings = dbcursor.fetchall()
    dbcursor.close()
    conn.close()

    # If the user has no bookings, display a message
    if len(bookings) == 0:
        return render_template('ticket.jinja2', username=session['username'], usertype=session['usertype'])

    # Otherwise, display the ticket information
    ticket_info = []
    for booking in bookings:
        transport_id = booking[2]
        conn = dbfunc.getConnection()
        if conn is None:
            print('DB connection Error')
            return redirect(url_for('index'))
        dbcursor = conn.cursor()
        dbcursor.execute('SELECT * FROM transportation WHERE transport_id=%s;', (transport_id,))
        transport = dbcursor.fetchone()
        dbcursor.close()
        conn.close()

        if transport is not None:
            deptCity = transport[1]
            arrivCity = transport[3]
            time_from = transport[2]
            time_to = transport[4]
            date_start = booking[3]
            date_end = booking[4]
            noOfseat = booking[5]
            totfare = booking[6]
            booking_id = booking[0]
            price = transport[5]
            ticket_info.append((booking_id, deptCity, arrivCity, date_start, date_end, time_from, time_to, noOfseat, totfare,price))

    return render_template('ticket.jinja2', ticket_info=ticket_info, username=session['username'], usertype=session['usertype'])


@app.route('/user/cancellation/<int:booking_id>', methods=['GET'])
def cancellation(booking_id):
    # Delete the booking from the database
    conn = dbfunc.getConnection()
    if conn is None:
        print('DB connection Error')
        return redirect(url_for('index'))
    dbcursor = conn.cursor()
    dbcursor.execute('DELETE FROM booking WHERE booking_id=%s;', (booking_id,))
    conn.commit()
    dbcursor.close()
    conn.close()

    return redirect(url_for('tickets'))

if __name__ == '__main__' :
    app.run(debug=True, port=5500, host='127.0.0.1')

