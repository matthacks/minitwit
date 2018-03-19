worker1: FLASK_APP=minitwit_api flask run
worker2: FLASK_APP=minitwit_api flask run -p 5050
worker3: FLASK_APP=minitwit_api flask run -p 5100
web1: FLASK_APP=minitwit flask run -p 5150
web2: FLASK_APP=minitwit flask run -p 5200
web3: FLASK_APP=minitwit flask run -p 5250
