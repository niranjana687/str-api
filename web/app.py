from operator import pos
from flask import Flask, jsonify, request
from pymongo import MongoClient
from flask_restful import Api, Resource
import bcrypt

app = Flask(__name__)
api = Api(app)

#connecting to mongo client
client = MongoClient('localhost', 27017)
db = client.sentenceDB
users = db["Users"] #user collection

#password checking
def checkPassword(username, password):
    hashed_pw = users.find_one({
        "Username":username
    })[0]["Password"]

    if bcrypt.hashow(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False

#verify the number of tokens with user
def verifyTokens(username):
    num_tokens = users.find_one({
        "Username":username
    })[0]["Tokens"]

    return num_tokens
#register end point 

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        #retrieve data from user
        username = postedData["username"]
        password = postedData["password"]

        #hashing
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert_one({
            "Username":username,
            "Password": hashed_pw,
            "Sentences": "",
            "Tokens": 10
        })

        retJSON = {
            "status": 200,
            "message": "successfully created an account"
        }

        return jsonify(retJSON)


# store data end point
class Store(Resource):
    def post(self):
        #get posted data
        posdtedData = request.get_json()
        
        #read posted data
        username = posdtedData["username"]
        password = posdtedData["password"]
        sentence = posdtedData["sentence"]

        #verify username password
        correct_pw = checkPassword(username, password)

        if not correct_pw:
            retJSON = {
                'status': 301,
                "message": "Incorrect username/password"
            }
            return jsonify(retJSON)
        
        #verify tokens
        num_tokens = verifyTokens(username)

        if num_tokens <= 0:
            retJSON = {
                'status': 302,
                "message": "Insufficient number of tokens"
            }
            return retJSON
        
        users.update_one({
            "Username": username
        }, {
            "$set": {
                "Sentence": sentence,
                "Tokens": num_tokens - 1
                }
        })

        retJSON = {
            "status": 200,
            "message": "sentence saved"
        }

        return jsonify(retJSON)


#get endpoint to retrieve sentence in return for token
class Get(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        check_pw = checkPassword(username, password)

        if not check_pw: 
            retJSON = {
                'status': 301,
                "message": "Incorrect username/password"
            }
            return jsonify(retJSON)
        
        num_tokens = verifyTokens(username)

        if num_tokens <=0:
            retJSON = {
                'status': 302,
                "message": "Insufficient number of tokens"
            }
            return retJSON
        
        sentence = users.find_one({"Username":username})[0]["Sentences"]

        users.update_one({
            "Username": username
        }, {
            "$set": {
                "Tokens": num_tokens - 1
                }
        })

        retJSON = {
            "status": 200,
            "message": str(sentence)
        }

        return jsonify(retJSON)




api.add_resource(Register, "/register")
api.add_resource(Store, "/store")
api.add_resource(Get, "/get")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)