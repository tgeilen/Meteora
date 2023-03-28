from web3.auto.gethdev import w3
from web3.middleware import geth_poa_middleware
from web3 import Web3
from accounts import Accounts
from wallet import Wallet
from ellipticCurve import EllipticCurve
from txOutput import TxOutput
from smartContract import SmartContract
import os
import json
import time

#this script can be used to test the functionality of the smart contract

#it may be necessary to decrease the gas price or the block size limit
#for the transactions to properly work without reaching the gas limit 

web3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545', request_kwargs={'timeout': 600}))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
	     
privateKey = '0x....................YourPrivateKeyAsHex.........................'

account = web3.eth.account.from_key(privateKey)

balance = web3.eth.get_balance(account.address)

with open('src/abi.json', 'r') as f:
    contract_abi = json.load(f)


print("Balance: " + str(balance))

web3.eth.default_account = account.address

#----------
contract_address = '0x....ContractAddressAsHex....'
#----------

contract = web3.eth.contract(address=contract_address, abi=contract_abi)

sender_address = account.address

balance1 = web3.eth.get_balance(sender_address)
print("Account balance beginning transaction: " +  str(balance1))


result = contract.functions.getTXoutputs().call()

print(result)


#create set of test accounts
sc = SmartContract()
accounts = Accounts(contract, sc)
wallet1 = accounts.getWallet(0)
wallet2 = accounts.getWallet(1)
wallet3 = accounts.getWallet(2)


sc = SmartContract()

listR = []
listBF = []

if (len(contract.functions.getTXoutputs().call()) == 0):
    for i in range(5):
        r = EllipticCurve.randomInt256()
        bf = EllipticCurve.randomInt256()
        tmpAddress = wallet2.createInitalOutputAdress(r,i)
        tx = TxOutput(10,bf,r, i, tmpAddress)
        txGen = contract.functions.receiveOutput(
            tx.getRPubKey(),
            tx.getAmmountCommitmentArray(),
            tx.getTransactionIndex(),
            [tmpAddress.x,tmpAddress.y]
        ).buildTransaction(
        {
        'from' :sender_address,
        'nonce' : web3.eth.get_transaction_count(sender_address),
        }
        )

        tx_create = web3.eth.account.sign_transaction(txGen, privateKey)

        # 7. Send tx and wait for receipt
        tx_hash = web3.eth.send_raw_transaction(tx_create.rawTransaction)
        tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)


        print(tx_receipt)
        sc.addTx(tx, tmpAddress)
        listR.append(r)
        listBF.append(bf)

    os.system("clear")

amount = 10

for i in range(10):
    bf = EllipticCurve.randomInt256()
    r = EllipticCurve.randomInt256()
    address = wallet1.createInitalOutputAdress(r,i)
    print("Adress in Setup:")
    print(address)
    
    txo = TxOutput(amount=amount, blindingFactor=bf, rPubkey=r, transactionIndex=i, address = address)

    wallet1.receiveTx(txo, bf, amount,address)

os.system("clear")

receivers = {(wallet3.getViewKey(), wallet3.getSignKey()): 10}


message , sig, outputs , sMLSAGS = (wallet1.createTransaction(receivers))


balance1 = web3.eth.get_balance(sender_address)
print("Account balance before transaction: " +  str(balance1))

txGen = contract.functions.receiveTransaction(
    int(message), 
    sMLSAGS[0]["c1"],
    sMLSAGS[0]["keyImage"],
    sMLSAGS[0]["rFactors"],
    sMLSAGS[0]["inputs"],
    outputs[0]["rPubKey"],
    outputs[0]["amountCommitment"],
    outputs[0]["transactionIndex"],
    outputs[0]["txAddress"]
    ).buildTransaction(
    {
    'from' :sender_address,
    'gas' : 4000000,
    'nonce' : web3.eth.get_transaction_count(sender_address)
    }
    )

tx_create = web3.eth.account.sign_transaction(txGen, privateKey)

startTime = time.time()
print(startTime)

# 7. Send tx and wait for receipt
tx_hash = web3.eth.send_raw_transaction(tx_create.rawTransaction)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
endTime = time.time()
print(tx_receipt)
print("Elapsed time: " + str(endTime-startTime))

balance2 = web3.eth.get_balance(sender_address)
print("Account balance after deployment: " +  str(balance2))
print("Execution cost: " + str((balance1 - balance2)))

print("done")


