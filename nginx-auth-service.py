#!/usr/bin/python3

import logging
from flask import Flask, abort, request, Response
import mysql.connector
import hashlib
import sys

app = Flask(__name__)

#log_level = logging.WARNING
log_level = logging.INFO
#log_level = 0 # to enable full logging of werkzeug's logger
auth_cache = []

def generate_hash(user, password):
  m = hashlib.md5()
  m.update("{}:{}".format(password, user).encode("utf-8"))
  return m.hexdigest()

def check_auth(user, password, mode):
  global auth_cache
  authorized = False
  auth_hash = generate_hash(user, password)
  if auth_hash in auth_cache:
    app.logger.info("Auth of {} from cache".format(user))
    return True
  else:
    app.logger.info("Auth of {} not from cache".format(user))
  try:
    cnx = mysql.connector.connect(user='user', passwd='password', database='auth_database')
  except Exception as e:
    app.logger.error("Failed to connect to database: {}".format(e))
    return False
  try:
    cursor = cnx.cursor()
    query = 'SELECT count(*) FROM user WHERE hash=%s'
    if mode == "admin":
      query += ' AND rechte="admin"'
    cursor.execute(query, (str(auth_hash),))
    authorized = next(cursor)[0] == 1
    cursor.close()
  except Exception as e:
    app.logger.error("Database error: {}".format(e))
  finally:
    cnx.close()
  if authorized:
    auth_cache += [auth_hash]
  return authorized

# https://stackoverflow.com/questions/7877230/standard-401-response-when-using-http-auth-in-flask
@app.errorhandler(401)
def custom_401(error):
  return Response('Access denied', 401, {'WWW-Authenticate': 'Basic realm="our.web.site"'})

@app.route('/auth', methods=['GET'])
def login():
  auth = request.authorization
  mode = request.headers.get("X-Auth-Mode")
  if auth is not None and check_auth(auth.username, auth.password, mode):
    return "Authentication successful"
  else:
    abort(401)

if __name__ == '__main__':
  # logs http requests to flask
  logging.getLogger('werkzeug').setLevel(log_level)
  # logs everything else using app.logger
  logging.getLogger(__name__).setLevel(log_level)
  app.run(host='::', port=9000)
