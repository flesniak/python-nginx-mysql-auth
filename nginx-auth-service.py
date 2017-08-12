#!/usr/bin/python3

from flask import Flask, abort, request
import mysql.connector
import hashlib

app = Flask(__name__)

def generate_hash(user, password):
  m = hashlib.md5()
  m.update("{}:{}".format(password, user).encode("utf-8"))
  return m.hexdigest()

def check_auth(user, password):
  auth_hash = generate_hash(user, password)
  try:
    cnx = mysql.connector.connect(user='user', passwd='password', database='auth_database')
    cursor = cnx.cursor()
    cursor.execute('SELECT count(*) FROM user WHERE hash=%s', (str(auth_hash),))
  except Exception as e:
    print("Database error: {}".format(e))
    return False
  authorized = next(cursor)[0] == 1
  cursor.close()
  cnx.close()
  return authorized

@app.route('/auth', methods=['GET'])
def login():
  auth = request.authorization
  if check_auth(auth.username, auth.password):
    return "Authentication successful"
  abort(401)

if __name__ == '__main__':
  app.run(port = 9000)
