import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    rows = db.execute('''SELECT symbols
        FROM transactions
        GROUP BY symbols
        HAVING user_id = ?
        AND SUM(shares) > 0
        ORDER BY symbols''', session["user_id"])

    subtotal = 0.0

    for row in rows:
        stock_data = lookup(row["symbols"])
        row["name"] = stock_data["name"]
        row["price"] = stock_data["price"]

        share_row = db.execute('''SELECT SUM(shares) AS sum_share
            FROM transactions
            GROUP BY symbols
            HAVING symbols = ?
            AND user_id = ?''', row["symbols"], session["user_id"])

        row["shares"] = share_row[0]["sum_share"]
        foobar = float(row["price"]) * float(row["shares"])
        subtotal += foobar
        row["total"] = f'${foobar:.2f}'

    cash_cal = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    cash = f"${cash_cal:.2f}"
    grant_total_cal = subtotal + cash_cal
    grant_total = f"${grant_total_cal:.2f}"

    return render_template("index.html", rows = rows, cash = cash, grant_total = grant_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        #Check if symbol is blank
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        #Use lookup
        symbol = request.form.get("symbol")
        stock_data = lookup(symbol)

        #Check if symbol is valid
        if not stock_data:
            return apology("Invalid symbol", 403)

        #Ensure shares is positive integer
        shares = int(request.form.get("shares"))
        if not shares > 0:
            return apology("Shares must be positive integer", 403)

        #Ensure user has enough cash
        rows = db.execute("SELECT cash FROM users WHERE id = ? ",
            session["user_id"])

        if float(rows[0]["cash"]) < stock_data["price"] * shares:
            return apology("Not enoguh cash in account")


        db.execute('''INSERT INTO transactions (user_id, symbols, shares, price)
            VALUES(?, ?, ?, ?)''', session["user_id"], symbol, shares, stock_data["price"])

        db.execute('''UPDATE users
            SET cash = cash - ?
            WHERE id = ?''', stock_data["price"] * shares, session["user_id"])

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = db.execute('''SELECT symbols, shares, transacted, price
        FROM transactions
        WHERE user_id = ?
        ORDER BY transacted DESC''', session["user_id"])

    for row in rows:
        if row["shares"] > 0:
            row["direction"] = "Bought"
        else:
            row["shares"] = row["shares"] * -1
            row["direction"] = "Sold"

    his_rows = db.execute('''SELECT cash, transacted
        FROM deposit
        WHERE user_id = ?''', session["user_id"])


    return render_template("history.html", rows=rows, his_rows=his_rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Must provide symbol", 403)

        # Use lookup
        stock_data = lookup(request.form.get("symbol"))

        #Handle null case
        if not stock_data:
            return apology("Invalid symbol", 403)

        # Redirect user to quoted
        return render_template("quoted.html", stock_data=stock_data)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        row = db.execute("SELECT * FROM users WHERE username = ? ", request.form.get("username"))

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure username has not existed
        elif len(row) == 1:
            return apology("username already exists", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        #Ensure confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation", 403)

        # Ensure confirmation was correct
        elif not request.form.get("confirmation") == request.form.get("password"):
            return apology("confirmation must equal to password", 403)

        #Hash the password
        password_hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        #Insert username and hash of password into the user database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), password_hash)

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        #Ensure a stock is selected
        if request.form.get("symbol") == "no_select":
            return apology("No stock selected", 403)

        #Ensure shares is positive integer & user owns enough stock
        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("Shares must be positive integer.", 403)

        stock_data = lookup(request.form.get("symbol"))

        db.execute('''INSERT INTO transactions
            (user_id, symbols, shares, price)
            VALUES (?, ?, ?, ?)''', session["user_id"], request.form.get("symbol"), int(request.form.get("shares"))*-1, stock_data["price"])

        db.execute('''UPDATE users
            SET cash = cash + ?
            WHERE id = ?''', stock_data["price"]*int(shares), session["user_id"])

        return redirect("/")

    else:
        rows = db.execute('''SELECT symbols
            FROM transactions
            GROUP BY symbols
            HAVING user_id = ?
            AND SUM(shares) > 0''', session["user_id"])

        #return apology if no stock in profolio
        if len(rows) < 1:
            return apology("No stock in profolio", 403)

        return render_template("sell.html", rows=rows)

@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    """Add cash"""
    if request.method == "POST":
        #Ensure positive number was enetered
        if not request.form.get("cash") or not float(request.form.get("cash")) or float(request.form.get("cash")) <= 0:
            return apology("Must provide positive number", 403)

        db.execute('''UPDATE users
            SET cash = cash + ?''', float(request.form.get("cash")))

        db.execute('''INSERT INTO deposit (user_id, cash)
            VALUES(?, ?)''', session["user_id"], float(request.form.get("cash")))

        return redirect("/")

    else:
        return render_template("deposit.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
