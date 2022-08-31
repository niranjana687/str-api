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

#register end point 

class Register(Resource):
    def post(self):
        postedData = request.get_json()

        #retrieve data from user
        username = postedData["username"]
        password = postedData["password"]

        #hashing
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt())

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


api.add_resource(Register, "/register")
api.add_resource(Store, "/store")

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)